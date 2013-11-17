(ns friend-form-sample.service
    (:require [io.pedestal.service.http :as bootstrap]
              [io.pedestal.service.http.route :as route]
              [io.pedestal.service.http.body-params :as body-params]
              [io.pedestal.service.http.route.definition :refer [defroutes]]
              [ring.util.response :as ring-resp]
              ;; requires below were added for sample
              [cemerick.friend :as friend]
              [cemerick.friend [credentials :as creds]
                               [workflows :as workflows]]
              [io.pedestal.service.http.ring-middlewares :as middlewares]
              [io.pedestal.service.interceptor :refer [definterceptorfn
                                                       interceptor]]
              [ring.middleware.session.cookie :as cookie]))

;; forward declarations of routing functions used in pages
(declare url-for form-action)

;; stub login action needed for routing purposes.
(def login-action (constantly nil))

;;; Regular page handlers. Basic string templates to keep things core

(defn home-page [_]
  (ring-resp/response
   (str "<html><body>"
        "Hello World!<br/>"
        (format "<a href=\"%s\">Protected Page</a>"
                (url-for ::protected-page))
        "</body></html>")))

(defn login-page
  [{{:keys [username]} :params}]
  (let [{:keys [action method]} (form-action ::login-action)]
    (ring-resp/response
     (str "<html><body>"
          (format "<form action=\"%s\" method=\"%s\">" action method)
          "User: <input type=\"text\" name=\"username\" value=\"" username "\">"
          "<br/>"
          "Pass: <input type=\"password\" name=\"password\">"
          "<br/>"
          "<input type=\"submit\" value=\"Login\">"
          "</form>"
          "</body></html>"))))

(defn logout-page [_]
  ;; redirect home and have your friend logout the user
  (-> (ring-resp/redirect "/")
      friend/logout*))

(def current-authentication
  "Dig around for info about request user"
  (comp friend/current-authentication :auth :friend/handler-map))

(defn protected-page [request]
  (let [username (-> request current-authentication :username)
        logout-url (url-for ::logout-page)]
    (ring-resp/response
     (format (str "<html><body>"
                  "Hello Admin!<br/>"
                  "Your username is \"%s\"</br>"
                  "<a href=\"%s\">Logout</a>"
                  "</body></html>")
             username
             logout-url))))

;;; Auth stuff

(def users
  "root/clojure login using bcrypt."
  (let [password (creds/hash-bcrypt "clojure")]
    {"root" {:username "root" :password password :roles #{::admin}}}))

(def friend-config
  "A friend config for interactive form use."
  {:login-uri "/login"
   :default-landing-uri "/admin/protected"
   :workflows [(workflows/interactive-form)]
   :credential-fn (partial creds/bcrypt-credential-fn users)})

(definterceptorfn friend-authenticate-interceptor
  "Creates a friend/authenticate interceptor for a given config."
  [auth-config]
  (interceptor
   :error
   (fn [{:keys [request] :as context} exception]
     ;; get exception details without Slingshot in this sample
     (let [exdata (ex-data exception)
           extype (-> exdata :object :cemerick.friend/type)]
       (if (#{:unauthorized} extype)
         ;; unauthorized errors should generate a response using catch handler
         (let [handler-map (:friend/handler-map request)
               response ((:catch-handler handler-map)  ;handler to use
                         (assoc (:request handler-map) ;feed exception back in
                           :cemerick.friend/authorization-failure exdata))]
           ;; respond with generated response
           (assoc context :response response))
         ;; re-throw other errors
         (throw exception))))
   :enter
   (fn [{:keys [request] :as context}]
     (let [response-or-handler-map
           (friend/authenticate-request request auth-config)]
       ;; a handler-map will exist in authenticated request if authenticated
       (if-let [handler-map (:friend/handler-map response-or-handler-map)]
         ;; friend authenticated the request, so continue
         (assoc-in context [:request :friend/handler-map] handler-map)
         ;; friend generated a response instead, so respond with it
         (assoc context :response response-or-handler-map))))
   :leave
   ;; hook up friend response handling
   (middlewares/response-fn-adapter friend/authenticate-response)))

(definterceptorfn friend-authorize-interceptor
  "Creates a friend interceptor for friend/authorize."
  [roles]
  (interceptor
   :enter
   (fn [{:keys [request] :as context}]
     (let [auth (:auth (:friend/handler-map request))]
       ;; check user has an authorized role
       (if (friend/authorized? roles auth)
         ;; authorized, so continue
         context
         ;; unauthorized, so throw exception for authentication interceptor
         (friend/throw-unauthorized auth {:cemerick.friend/required-roles
                                          roles}))))))

(defroutes routes
  [[["/" {:get home-page}
     ;; Set default interceptors for /about and any other paths under /
     ^:interceptors [(body-params/body-params)
                     bootstrap/html-body
                     ;; fix for interactive-form workflow
                     middlewares/keyword-params
                     ;; session is required by interactive-form workflow
                     (middlewares/session {:store (cookie/cookie-store)})
                     ;; sample authenticate request
                     (friend-authenticate-interceptor friend-config)]
     ["/login" {:get login-page :post login-action}]
     ["/logout" {:get logout-page}]
     ["/admin"
      ^:interceptors [;; sample authorize request
                      (friend-authorize-interceptor #{::admin})]
      ["/protected" {:get protected-page}]]]]])

;; handy routing functions
(def url-for (route/url-for-routes routes))
(def form-action (route/form-action-for-routes routes))

;; Consumed by friend-form-sample.server/create-server
;; See bootstrap/default-interceptors for additional options you can configure
(def service {:env :prod
              ;; You can bring your own non-default interceptors. Make
              ;; sure you include routing and set it up right for
              ;; dev-mode. If you do, many other keys for configuring
              ;; default interceptors will be ignored.
              ;; :bootstrap/interceptors []
              ::bootstrap/routes routes

              ;; Uncomment next line to enable CORS support, add
              ;; string(s) specifying scheme, host and port for
              ;; allowed source(s):
              ;;
              ;; "http://localhost:8080"
              ;;
              ;;::bootstrap/allowed-origins ["scheme://host:port"]

              ;; Root for resource interceptor that is available by default.
              ::bootstrap/resource-path "/public"

              ;; Either :jetty or :tomcat (see comments in project.clj
              ;; to enable Tomcat)
              ;;::bootstrap/host "localhost"
              ::bootstrap/type :jetty
              ::bootstrap/port 8080})
