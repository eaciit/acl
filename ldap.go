package acl

import (
	"errors"
	"fmt"
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

func GetLdapMemberOfGroup(groupid string, conf toolkit.M) (members []*User, err error) {

	members = make([]*User, 0, 0)

	arrtkm, err := FindDataLdap(toolkit.ToString(conf["address"]), toolkit.ToString(conf["basedn"]), toolkit.ToString(conf["filter"]), conf)
	if err != nil {
		err = errors.New(fmt.Sprintf("Find Data, found : %v", err.Error()))
		return
	}

	maptkm, err := toolkit.ToM(conf["mapattributes"])
	if err != nil {
		return
	}

	for _, val := range arrtkm {
		member := new(User)
		member.ID = toolkit.RandomString(32)
		member.LoginID = toolkit.ToString(val.Get(toolkit.ToString(maptkm.Get("LoginID", "")), ""))
		member.FullName = toolkit.ToString(val.Get(toolkit.ToString(maptkm.Get("FullName", "")), ""))
		member.Email = toolkit.ToString(val.Get(toolkit.ToString(maptkm.Get("Email", "")), ""))
		member.Enable = true
		member.LoginType = LogTypeLdap
		member.LoginConf = toolkit.M{}.Set("address", toolkit.ToString(conf["address"])).Set("basedn", toolkit.ToString(conf["basedn"]))
		member.AddToGroup(groupid)

		if member.LoginID != "" {
			members = append(members, member)
		}
	}

	return
}

//Check existing user, if any add group. and set enable
func AddUserLdapByGroup(groupid string, conf toolkit.M) (err error) {
	// arrtkm = make([]toolkit.M, 0, 0)
	//addr, basedn, filter string, param toolkit.M
	if !conf.Has("address") || !conf.Has("basedn") || !conf.Has("filter") || !conf.Has("attributes") || !conf.Has("mapattributes") {
		err = errors.New("The config is not completed")
		return
	}

	members, err := GetLdapMemberOfGroup(groupid, conf)

	if err != nil {
		err = errors.New(fmt.Sprintf("Add By Group found error when get member : %v", err.Error()))
		return
	}

	if len(members) == 0 {
		return
	}

	// atUsers, err := GetUserByGroup(groupid)
	// if err != nil {
	// 	err = errors.New(fmt.Sprintf("Add By Group found error when get user by group : %v", err.Error()))
	// 	return
	// }

	for _, val := range members {

		tUser := new(User)
		err = FindUserByLoginID(tUser, val.LoginID)
		if err != nil {
			return
		}

		// for _, uval := range atUsers {
		// 	if uval.LoginID == val.LoginID {
		// 		uval.AddToGroup(groupid)
		// 		val = uval
		// 	}
		// }

		if tUser.LoginID == val.LoginID {
			tUser.AddToGroup(groupid)
			err = Save(tUser)
		} else {
			err = Save(val)
		}

		if err != nil {
			return
		}

	}

	return
}

//if group len == 0, delete user
func RefreshUserLdapByGroup(groupid string, conf toolkit.M) (err error) {
	if !conf.Has("address") || !conf.Has("basedn") || !conf.Has("filter") || !conf.Has("attributes") || !conf.Has("mapattributes") {
		err = errors.New("The config is not completed")
		return
	}

	members, err := GetLdapMemberOfGroup(groupid, conf)

	if err != nil {
		err = errors.New(fmt.Sprintf("Add By Group found error where get member : %v", err.Error()))
		return
	}

	arrUsers, err := GetUserByGroup(groupid)
	if err != nil {
		err = errors.New(fmt.Sprintf("Add By Group found error when get user by group : %v", err.Error()))

		return
	}

	if len(arrUsers) == 0 && len(members) == 0 {
		return
	}

	for _, val := range arrUsers {
		in := 0
		flag := false

		for i, tval := range members {
			if val.LoginID == tval.LoginID {
				flag = true
				in = i + 1
				break
			}
		}

		if flag {
			if in < len(members) {
				members = append(members[:in], members[in+1:]...)
			} else {
				members = members[:in]
			}
		} else {
			val.RemoveFromGroup(groupid)
			if len(val.Groups) == 0 {
				err = Delete(val)
			} else {
				err = Save(val)
			}

			if err != nil {
				return
			}
		}
	}

	for _, val := range members {
		tUser := new(User)
		err = FindUserByLoginID(tUser, val.LoginID)
		if err != nil {
			return
		}

		if tUser.LoginID == val.LoginID {
			tUser.AddToGroup(groupid)
			err = Save(tUser)
		} else {
			err = Save(val)
		}

		if err != nil {
			return
		}

	}

	return
}

//Refresh user based on enable and disable
