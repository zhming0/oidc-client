;; clj -M:dev -e "(load-file \"dev/repl.clj\")"
;; or
;; clj -M:dev
;; then (start-repl)
(ns user
  (:require
    [jsonista.core :as j]
    [oidc-client.core :as oidc]))


(def config nil)


(defn start-repl
  []
  (println "oidc-client REPL")
  (println "Example usage:")
  (println "  (def meta (oidc/discover \"https://accounts.google.com\"))")
  (println "  (def config (oidc/configuration meta \"your-client-id\" {:client-secret \"secret\"}))")
  (println "  (def auth-url (oidc/build-authorization-url config {:redirect_uri \"http://localhost:8080/callback\" :scope \"openid email\"}))"))


(defn demo
  []
  (let [meta (oidc/discover "https://accounts.google.com")
        cfg  (oidc/configuration meta "demo")]
    (println "Server metadata issuer:" (:issuer meta))
    cfg))
