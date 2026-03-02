(ns oidc-client.core-test
  (:require
    [clojure.test :refer :all]
    [jsonista.core :as j]
    [oidc-client.core :as oidc])
  (:import
    (com.sun.net.httpserver
      HttpHandler
      HttpServer)
    (java.net
      InetSocketAddress)
    (java.util.concurrent
      Executors)))


;; ---------------------------------------------------------------------------
;; Ephemeral test OIDC server
;; ---------------------------------------------------------------------------

(def ^:dynamic *test-server* nil)


(defn- write-json
  [x]
  (j/write-value-as-string x))


(defn- form-decode
  "Minimal x-www-form-urlencoded decoder for test use."
  [s]
  (when (seq s)
    (into {}
          (map (fn [pair]
                 (let [[k v] (clojure.string/split pair #"=" 2)]
                   [(java.net.URLDecoder/decode (or k "") "UTF-8")
                    (java.net.URLDecoder/decode (or v "") "UTF-8")])))
          (clojure.string/split s #"&"))))


(defn- discovery-doc
  [issuer]
  {:issuer                                issuer
   :authorization_endpoint                (str issuer "/authorize")
   :token_endpoint                        (str issuer "/token")
   :userinfo_endpoint                     (str issuer "/userinfo")
   :revocation_endpoint                   (str issuer "/revoke")
   :introspection_endpoint                (str issuer "/introspect")
   :end_session_endpoint                  (str issuer "/logout")
   :jwks_uri                              (str issuer "/jwks")
   :response_types_supported              ["code"]
   :grant_types_supported                 ["authorization_code" "refresh_token" "client_credentials"]
   :token_endpoint_auth_methods_supported ["client_secret_basic" "client_secret_post" "none"]
   :code_challenge_methods_supported      ["S256"]
   :scopes_supported                      ["openid" "email" "profile"]})


(def ^:private test-token-response
  {:access_token  "test-access-token"
   :token_type    "Bearer"
   :expires_in    3600
   :refresh_token "test-refresh-token"
   :id_token      "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.fake"})


(def ^:private test-userinfo
  {:sub   "1234567890"
   :name  "John Doe"
   :email "john@example.com"})


(def ^:private test-introspection
  {:active true
   :sub    "1234567890"
   :scope  "openid email"})


(defn- handler
  "Build an HttpHandler that dispatches on path."
  [base-url]
  (reify HttpHandler
    (handle
      [_ exchange]
      (let [path (.getPath (.getRequestURI exchange))
            send (fn [status ^String body]
                   (let [bs (.getBytes body "UTF-8")]
                     (.add (.getResponseHeaders exchange) "Content-Type" "application/json")
                     (.sendResponseHeaders exchange status (alength bs))
                     (with-open [os (.getResponseBody exchange)]
                       (.write os bs))))
            send-empty (fn [status]
                         (.sendResponseHeaders exchange status -1))]
        (case path
          "/.well-known/openid-configuration"
          (send 200 (write-json (discovery-doc base-url)))

          "/token"
          (let [body-str (slurp (.getRequestBody exchange))
                params   (form-decode body-str)
                gt       (get params "grant_type")]
            (if (contains? #{"authorization_code" "refresh_token" "client_credentials"} gt)
              (send 200 (write-json test-token-response))
              (send 400 (write-json {:error "unsupported_grant_type"}))))

          "/userinfo"
          (let [auth (-> exchange .getRequestHeaders (.getFirst "Authorization"))]
            (if (and auth (clojure.string/starts-with? auth "Bearer "))
              (send 200 (write-json test-userinfo))
              (send-empty 401)))

          "/revoke"
          (send-empty 200)

          "/introspect"
          (send 200 (write-json test-introspection))

          "/logout"
          (send-empty 200)

          ;; fallback
          (send-empty 404))))))


(defn- start-server
  []
  (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
    (.setExecutor server (Executors/newFixedThreadPool 2))
    (let [port     (.getPort (.getAddress server))
          base-url (str "http://127.0.0.1:" port)]
      (.createContext server "/" (handler base-url))
      (.start server)
      {:server server :port port :base-url base-url})))


(defn- stop-server
  [{:keys [server]}]
  (.stop ^HttpServer server 0))


(defn server-fixture
  [f]
  (let [s (start-server)]
    (binding [*test-server* s]
      (try (f) (finally (stop-server s))))))


(use-fixtures :each server-fixture)


(defn- base-url
  []
  (:base-url *test-server*))


;; ---------------------------------------------------------------------------
;; Tests
;; ---------------------------------------------------------------------------

(deftest discovery-test
  (let [meta (oidc/discover (base-url))]
    (is (= (base-url) (:issuer meta)))
    (is (= (str (base-url) "/authorize") (:authorization_endpoint meta)))
    (is (= (str (base-url) "/token") (:token_endpoint meta)))))


(deftest configuration-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "my-client" {:client-secret "s3cret"})]
    (is (= "my-client" (:client-id config)))
    (is (= "s3cret" (:client-secret config)))
    (is (= :client-secret-post (:auth-method config)))))


(deftest build-authorization-url-test
  (let [meta    (oidc/discover (base-url))
        config  (oidc/configuration meta "test-client")
        auth-url (oidc/build-authorization-url config
                                               {:redirect_uri "http://localhost:8080/callback"
                                                :scope        "openid email"})]
    (is (string? auth-url))
    (is (re-find #"response_type=code" auth-url))
    (is (re-find #"client_id=test-client" auth-url))
    (is (re-find #"redirect_uri=" auth-url))
    (is (re-find #"scope=openid" auth-url))))


(deftest pkce-test
  (let [verifier  (oidc/random-pkce-code-verifier)
        challenge (oidc/pkce-code-challenge verifier)]
    (is (string? verifier))
    (is (>= (count verifier) 32))
    (is (string? challenge))
    (is (= 43 (count challenge)))
    (testing "different verifiers produce different challenges"
      (is (not= challenge (oidc/pkce-code-challenge (oidc/random-pkce-code-verifier)))))))


(deftest random-state-nonce-test
  (let [s1 (oidc/random-state)
        s2 (oidc/random-state)]
    (is (string? s1))
    (is (>= (count s1) 32))
    (is (not= s1 s2)))
  (let [n1 (oidc/random-nonce)
        n2 (oidc/random-nonce)]
    (is (string? n1))
    (is (not= n1 n2))))


(deftest authorization-code-grant-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client" {:client-secret "secret"})
        tokens (oidc/authorization-code-grant config
                                              {:code          "test-code"
                                               :redirect_uri  "http://localhost:8080/callback"
                                               :code_verifier "test-verifier"})]
    (is (= "test-access-token" (:access_token tokens)))
    (is (= "Bearer" (:token_type tokens)))
    (is (= "test-refresh-token" (:refresh_token tokens)))
    (is (some? (:id_token tokens)))))


(deftest refresh-token-grant-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client" {:client-secret "secret"})
        tokens (oidc/refresh-token-grant config "old-refresh-token")]
    (is (= "test-access-token" (:access_token tokens)))))


(deftest client-credentials-grant-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client" {:client-secret "secret"})
        tokens (oidc/client-credentials-grant config {:scope "openid"})]
    (is (= "test-access-token" (:access_token tokens)))))


(deftest fetch-userinfo-test
  (let [meta     (oidc/discover (base-url))
        config   (oidc/configuration meta "test-client")
        userinfo (oidc/fetch-userinfo config "test-access-token")]
    (is (= "1234567890" (:sub userinfo)))
    (is (= "John Doe" (:name userinfo)))
    (is (= "john@example.com" (:email userinfo)))))


(deftest revoke-token-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client" {:client-secret "secret"})]
    (is (nil? (oidc/revoke-token config "some-token")))))


(deftest introspect-token-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client" {:client-secret "secret"})
        result (oidc/introspect-token config "some-token")]
    (is (true? (:active result)))
    (is (= "1234567890" (:sub result)))))


(deftest build-end-session-url-test
  (let [meta   (oidc/discover (base-url))
        config (oidc/configuration meta "test-client")
        url    (oidc/build-end-session-url config
                                           {:id_token_hint            "tok"
                                            :post_logout_redirect_uri "http://localhost/bye"})]
    (is (string? url))
    (is (re-find #"client_id=test-client" url))
    (is (re-find #"id_token_hint=tok" url))))


(deftest supports-pkce-test
  (let [meta (oidc/discover (base-url))]
    (is (true? (oidc/supports-pkce? meta)))
    (is (false? (oidc/supports-pkce? (dissoc meta :code_challenge_methods_supported))))))


(deftest end-session-missing-endpoint-test
  (let [meta   (dissoc (oidc/discover (base-url)) :end_session_endpoint)
        config (oidc/configuration meta "test-client")]
    (is (thrown-with-msg? Exception #"No end_session_endpoint"
          (oidc/build-end-session-url config)))))
