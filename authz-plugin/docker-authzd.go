package main

import (
	"github.com/docker/go-plugins-helpers/authorization"
	//"github.com/docker/docker/pkg/authorization"
	log "github.com/Sirupsen/logrus"
	//"./core"
	"net/http"
)

const (
	defaultDockerHost = "unix:///var/run/docker.sock"
	defaultPluginSocket = "/var/run/docker/plugins/ldap_authz_plugin.sock"
)

type LdapAuthzPlugin struct{}

func (p *LdapAuthzPlugin) AuthZRes(req authorization.Request) authorization.Response {
	log.Printf("AuthZRes %+v", req)
	//log.WithField("req", req).Info("AuthZRes")
	return authorization.Response{Allow: true}
}

func (p *LdapAuthzPlugin) AuthZReq(req authorization.Request) authorization.Response {
	log.Printf("AuthZReq %+v", req)

	return authorization.Response{Allow: true}
}

func dump(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s",r.Body)
}

func main() {
	p := &LdapAuthzPlugin{}
	h := authorization.NewHandler(p)
	//port := ":8989"
	log.Println("Start server")
	//h.ServeTCP("ldap_authz_plugin", port)
	h.ServeUnix("root",defaultPluginSocket)
	http.HandleFunc("/", dump)
	//http.ListenAndServe(port, nil)

}