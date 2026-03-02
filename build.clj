(ns build
  (:require
    [clojure.tools.build.api :as b]
    [deps-deploy.deps-deploy :as dd]))


(def lib 'io.github.zhming0/oidc-client)
(def class-dir "target/classes")
(def jar-file "target/oidc-client.jar")


(defn- version
  []
  (or (System/getenv "VERSION")
      (b/git-count-revs nil)))


(defn- pom-opts
  [opts]
  (let [v (version)]
    (assoc opts
           :lib lib
           :version v
           :basis (b/create-basis {})
           :class-dir class-dir
           :jar-file jar-file
           :src-dirs ["src"]
           :scm {:url "https://github.com/zhming0/oidc-client"
                 :tag v}
           :pom-data [[:description "OpenID Connect / OAuth 2.0 client library for Clojure"]
                      [:url "https://github.com/zhming0/oidc-client"]
                      [:licenses
                       [:license
                        [:name "EPL-2.0"]
                        [:url "https://www.eclipse.org/legal/epl-2.0/"]]]])))


(defn clean
  [opts]
  (b/delete {:path "target"})
  opts)


(defn jar
  [opts]
  (let [opts (pom-opts opts)
        v    (version)]
    (clean opts)
    (b/write-pom opts)
    (.mkdirs (java.io.File. "resources/oidc_client"))
    (spit "resources/oidc_client/version.txt" v)
    (b/copy-dir {:src-dirs ["src" "resources"]
                 :target-dir class-dir})
    (b/jar opts)
    (println "Built" jar-file "version" v)
    opts))


(defn deploy
  "Deploy to Clojars. Requires CLOJARS_USERNAME and CLOJARS_PASSWORD env vars."
  [opts]
  (jar opts)
  (dd/deploy {:installer :remote
              :artifact (b/resolve-path jar-file)
              :pom-file (b/pom-path (pom-opts opts))})
  (println "Deployed" lib (version) "to Clojars")
  opts)
