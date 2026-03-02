(ns oidc-client.core
  "OpenID Connect / OAuth 2.0 client library for Clojure.
   Port of https://github.com/panva/openid-client"
  (:require
    [babashka.http-client :as http]
    [clojure.java.io :as io]
    [clojure.string :as str]
    [jsonista.core :as j])
  (:import
    (java.net
      URLEncoder)
    (java.security
      MessageDigest
      SecureRandom)
    (java.util
      Base64)))


;; ---------------------------------------------------------------------------
;; JSON
;; ---------------------------------------------------------------------------

(def ^:private json-mapper (j/object-mapper {:decode-key-fn keyword}))


(defn- read-json
  [s]
  (j/read-value s json-mapper))


(defn- write-json
  [x]
  (j/write-value-as-string x))


;; ---------------------------------------------------------------------------
;; Helpers
;; ---------------------------------------------------------------------------

(def version
  (or (some-> (io/resource "oidc_client/version.txt") slurp str/trim)
      "dev"))


(def user-agent (str "oidc-client/" version))


(defn- url-encode
  [s]
  (URLEncoder/encode (str s) "UTF-8"))


(defn- form-encode
  "Encode a map as application/x-www-form-urlencoded."
  [params]
  (->> params
       (map (fn [[k v]] (str (url-encode (name k)) "=" (url-encode v))))
       (str/join "&")))


(defn random-bytes
  "Return `n` cryptographically random bytes."
  [n]
  (let [buf (byte-array n)]
    (.nextBytes (SecureRandom.) buf)
    buf))


(defn base64url-encode
  "Base64url-encode bytes (no padding)."
  ^String [^bytes bs]
  (-> (Base64/getUrlEncoder)
      (.withoutPadding)
      (.encodeToString bs)))


(defn base64url-decode
  "Base64url-decode a string to bytes."
  ^bytes [^String s]
  (.decode (Base64/getUrlDecoder) s))


;; ---------------------------------------------------------------------------
;; PKCE / random values
;; ---------------------------------------------------------------------------

(defn random-state
  "Generate a random `state` parameter value."
  []
  (base64url-encode (random-bytes 32)))


(defn random-nonce
  "Generate a random `nonce` parameter value."
  []
  (base64url-encode (random-bytes 32)))


(defn random-pkce-code-verifier
  "Generate a random PKCE `code_verifier`."
  []
  (base64url-encode (random-bytes 32)))


(defn pkce-code-challenge
  "Compute the S256 PKCE `code_challenge` for the given `code-verifier`."
  [code-verifier]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (base64url-encode (.digest digest (.getBytes ^String code-verifier "US-ASCII")))))


;; ---------------------------------------------------------------------------
;; HTTP helpers (using babashka.http-client)
;; ---------------------------------------------------------------------------

(def ^:private default-headers
  {"user-agent" user-agent
   "accept"     "application/json"})


(defn- request
  "Thin wrapper around babashka.http-client. Returns {:status :body :headers}."
  [{:keys [method url headers body]}]
  (let [opts (cond-> {:headers (merge default-headers headers)
                      :throw   false}
               body (assoc :body body))
        resp (case method
               :get  (http/get  url opts)
               :post (http/post url opts))]
    {:status  (:status resp)
     :body    (:body resp)
     :headers (:headers resp)}))


(defn- assert-ok!
  [resp context]
  (when-not (<= 200 (:status resp) 299)
    (throw (ex-info (str context " failed with status " (:status resp))
                    {:status (:status resp)
                     :body   (:body resp)}))))


;; ---------------------------------------------------------------------------
;; Discovery
;; ---------------------------------------------------------------------------

(defn- well-known-url
  [issuer]
  (let [base (str issuer)]
    (if (str/ends-with? base "/")
      (str base ".well-known/openid-configuration")
      (str base "/.well-known/openid-configuration"))))


(defn discover
  "Fetch the OpenID Connect discovery document for `issuer`.
   Returns the parsed server metadata map (keys are keywords matching
   the standard JSON field names, e.g. :authorization_endpoint)."
  [issuer]
  (let [resp (request {:method :get :url (well-known-url issuer)})]
    (assert-ok! resp "Discovery")
    (read-json (:body resp))))


;; ---------------------------------------------------------------------------
;; Configuration
;; ---------------------------------------------------------------------------

(defn configuration
  "Build a client configuration.

   `server-metadata` - map returned by `discover` (or constructed manually)
   `client-id`       - OAuth 2.0 client identifier
   `opts`            - optional map:
     :client-secret       - client secret (string)
     :redirect-uris       - vector of redirect URIs
     :token-endpoint-auth-method - keyword, one of:
         :client-secret-post (default when secret present)
         :client-secret-basic
         :none (default when no secret)"
  [server-metadata client-id & [{:keys [client-secret
                                        redirect-uris
                                        token-endpoint-auth-method]}]]
  (let [auth-method (or token-endpoint-auth-method
                        (if client-secret :client-secret-post :none))]
    {:server        server-metadata
     :client-id     client-id
     :client-secret client-secret
     :redirect-uris redirect-uris
     :auth-method   auth-method}))


;; ---------------------------------------------------------------------------
;; Client authentication
;; ---------------------------------------------------------------------------

(defn- auth-headers
  "Return extra headers / body params for the configured auth method."
  [{:keys [client-id client-secret auth-method]}]
  (case auth-method
    :client-secret-basic
    {:headers {"authorization"
               (str "Basic "
                    (base64url-encode
                      (.getBytes (str (url-encode client-id) ":" (url-encode client-secret))
                                 "UTF-8")))}}

    :client-secret-post
    {:params {"client_id"     client-id
              "client_secret" client-secret}}

    ;; :none or anything else
    {:params {"client_id" client-id}}))


;; ---------------------------------------------------------------------------
;; Helpers for token-endpoint calls
;; ---------------------------------------------------------------------------

(defn- token-endpoint-request
  "POST to the token endpoint with auth + extra params. Returns parsed JSON."
  [config extra-params]
  (let [server (:server config)
        token-ep (or (:token_endpoint server)
                     (throw (ex-info "No token_endpoint in server metadata" {:server server})))
        {:keys [headers params]} (auth-headers config)
        all-params (merge params extra-params)
        resp (request {:method  :post
                       :url     token-ep
                       :headers (merge {"content-type" "application/x-www-form-urlencoded"} headers)
                       :body    (form-encode all-params)})]
    (assert-ok! resp "Token endpoint")
    (read-json (:body resp))))


;; ---------------------------------------------------------------------------
;; Authorization URL
;; ---------------------------------------------------------------------------

(defn build-authorization-url
  "Build the authorization URL the user-agent should be redirected to.

   `config`      - configuration map from `configuration`
   `params`      - map of authorization request params, e.g.:
     :redirect_uri, :scope, :state, :nonce,
     :code_challenge, :code_challenge_method,
     :response_type (default \"code\"), :response_mode, etc."
  [config params]
  (let [server (:server config)
        auth-ep (or (:authorization_endpoint server)
                    (throw (ex-info "No authorization_endpoint in server metadata" {:server server})))
        defaults {"response_type" "code"
                  "client_id"     (:client-id config)}
        merged (merge defaults
                      (reduce-kv (fn [m k v] (assoc m (name k) (str v))) {} params))
        qs (form-encode merged)]
    (str auth-ep "?" qs)))


;; ---------------------------------------------------------------------------
;; Grants
;; ---------------------------------------------------------------------------

(defn authorization-code-grant
  "Exchange an authorization `code` for tokens.

   `opts` map keys:
     :code           - the authorization code (required)
     :redirect_uri   - must match the one used in the authorization request
     :code_verifier  - PKCE code verifier (when PKCE was used)"
  [config opts]
  (let [{:keys [code redirect_uri code_verifier]} opts]
    (assert code "code is required")
    (assert redirect_uri "redirect_uri is required")
    (token-endpoint-request config
                            (cond-> {"grant_type"   "authorization_code"
                                     "code"         code
                                     "redirect_uri" redirect_uri}
                              code_verifier (assoc "code_verifier" code_verifier)))))


(defn refresh-token-grant
  "Use a `refresh-token` to obtain new tokens.

   `extra-params` - optional map of additional params (e.g. :scope, :resource)."
  [config refresh-token & [extra-params]]
  (token-endpoint-request config
                          (merge {"grant_type"    "refresh_token"
                                  "refresh_token" refresh-token}
                                 (when extra-params
                                   (reduce-kv (fn [m k v] (assoc m (name k) (str v))) {} extra-params)))))


(defn client-credentials-grant
  "Perform a client credentials grant.

   `extra-params` - optional map (e.g. :scope, :resource)."
  [config & [extra-params]]
  (token-endpoint-request config
                          (merge {"grant_type" "client_credentials"}
                                 (when extra-params
                                   (reduce-kv (fn [m k v] (assoc m (name k) (str v))) {} extra-params)))))


;; ---------------------------------------------------------------------------
;; UserInfo
;; ---------------------------------------------------------------------------

(defn fetch-userinfo
  "Fetch claims from the UserInfo endpoint using `access-token`."
  [config access-token]
  (let [server (:server config)
        ep (or (:userinfo_endpoint server)
               (throw (ex-info "No userinfo_endpoint in server metadata" {:server server})))
        resp (request {:method  :get
                       :url     ep
                       :headers {"authorization" (str "Bearer " access-token)}})]
    (assert-ok! resp "UserInfo")
    (read-json (:body resp))))


;; ---------------------------------------------------------------------------
;; Token revocation
;; ---------------------------------------------------------------------------

(defn revoke-token
  "Revoke a token at the revocation endpoint.

   `opts` - optional map with :token_type_hint (\"access_token\" or \"refresh_token\")."
  [config token & [opts]]
  (let [server (:server config)
        ep (or (:revocation_endpoint server)
               (throw (ex-info "No revocation_endpoint in server metadata" {:server server})))
        {:keys [headers params]} (auth-headers config)
        all-params (merge params
                          {"token" token}
                          (when-let [hint (:token_type_hint opts)]
                            {"token_type_hint" hint}))
        resp (request {:method  :post
                       :url     ep
                       :headers (merge {"content-type" "application/x-www-form-urlencoded"} headers)
                       :body    (form-encode all-params)})]
    (when-not (contains? #{200 204} (:status resp))
      (throw (ex-info (str "Token revocation failed with status " (:status resp))
                      {:status (:status resp) :body (:body resp)})))))


;; ---------------------------------------------------------------------------
;; Token introspection
;; ---------------------------------------------------------------------------

(defn introspect-token
  "Introspect a token. Returns the parsed introspection response."
  [config token & [opts]]
  (let [server (:server config)
        ep (or (:introspection_endpoint server)
               (throw (ex-info "No introspection_endpoint in server metadata" {:server server})))
        {:keys [headers params]} (auth-headers config)
        all-params (merge params
                          {"token" token}
                          (when-let [hint (:token_type_hint opts)]
                            {"token_type_hint" hint}))
        resp (request {:method  :post
                       :url     ep
                       :headers (merge {"content-type" "application/x-www-form-urlencoded"} headers)
                       :body    (form-encode all-params)})]
    (assert-ok! resp "Token introspection")
    (read-json (:body resp))))


;; ---------------------------------------------------------------------------
;; End-session / logout
;; ---------------------------------------------------------------------------

(defn build-end-session-url
  "Build a RP-Initiated Logout URL.

   `params` - optional map with :id_token_hint, :post_logout_redirect_uri, :state."
  [config & [params]]
  (let [server (:server config)
        ep (or (:end_session_endpoint server)
               (throw (ex-info "No end_session_endpoint in server metadata" {:server server})))
        defaults {"client_id" (:client-id config)}
        merged (merge defaults
                      (when params
                        (reduce-kv (fn [m k v] (assoc m (name k) (str v))) {} params)))
        qs (form-encode merged)]
    (str ep "?" qs)))


;; ---------------------------------------------------------------------------
;; Protected resource
;; ---------------------------------------------------------------------------

(defn fetch-protected-resource
  "Make a GET request to a protected resource with the given `access-token`.

   Returns {:status :body :headers}."
  [access-token url & [{:keys [method] :or {method :get}}]]
  (request {:method  method
            :url     url
            :headers {"authorization" (str "Bearer " access-token)}}))


;; ---------------------------------------------------------------------------
;; Convenience: supports-pkce?
;; ---------------------------------------------------------------------------

(defn supports-pkce?
  "Returns true if the server metadata indicates S256 PKCE support."
  [server-metadata]
  (let [methods (:code_challenge_methods_supported server-metadata)]
    (boolean (some #{"S256"} methods))))
