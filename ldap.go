package acl

import (
	"github.com/eaciit/ldap"
	"github.com/eaciit/toolkit"
)

func checkloginldap(username string, password string, loginconf toolkit.M) (cond bool) {
	cond = false

	l := ldap.NewConnection(toolkit.ToString(loginconf["address"]))
	err := l.Connect()
	if err != nil {
		return
	}
	defer l.Close()

	err = l.Bind(username, password)
	if err == nil {
		cond = true
	}

	return
}

func FindDataLdap(addr, basedn, filter string, param toolkit.M) (arrtkm []toolkit.M, err error) {
	arrtkm = make([]toolkit.M, 0, 0)

	l := ldap.NewConnection(addr)
	err = l.Connect()
	if err != nil {
		return
	}
	defer l.Close()

	if param.Has("username") {
		err = l.Bind(toolkit.ToString(param["username"]), toolkit.ToString(param["password"]))
		if err != nil {
			return
		}
	}

	attributes := make([]string, 0, 0)
	if param.Has("attributes") {
		attributes = param["attributes"].([]string)
	}
	// filter = "(*" + filter + "*)"
	search := ldap.NewSearchRequest(basedn,
		ldap.ScopeWholeSubtree,
		ldap.DerefAlways,
		0,
		0,
		false,
		filter,
		attributes,
		nil)

	sr, err := l.Search(search)

	for _, v := range sr.Entries {
		tkm := toolkit.M{}

		for _, str := range attributes {
			if len(v.GetAttributeValues(str)) > 1 {
				tkm.Set(str, v.GetAttributeValues(str))
			} else {
				tkm.Set(str, v.GetAttributeValue(str))
			}
		}

		if len(tkm) > 0 {
			arrtkm = append(arrtkm, tkm)
		}
	}

	return
}

//Check existing user, if any add group. and set enable
func AddUserLdapByGroup(member []toolkit.M) (err error) {
	// arrtkm = make([]toolkit.M, 0, 0)

	return
}

//if group len == 0, delete user
func RefreshUserLdapByGroup(member []toolkit.M) (err error) {
	// arrtkm = make([]toolkit.M, 0, 0)

	return
}

//Refresh user based on enable and disable
