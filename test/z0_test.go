package acl

import (
	"fmt"

	"github.com/eaciit/acl"
	"github.com/eaciit/dbox"
	_ "github.com/eaciit/dbox/dbc/mongo"
	"github.com/eaciit/toolkit"
	// "os"
	// "path/filepath"
	"testing"
	"time"
)

// var err error

// func init() {
// 	conn, err := prepareconnection()

// 	if err != nil {
// 		t.Errorf("Error connecting to database: %s \n", e.Error())
// 	}
// }

func prepareconnection() (conn dbox.IConnection, err error) {
	conn, err = dbox.NewConnection("mongo",
		&dbox.ConnectionInfo{"localhost:27017", "valegrab", "", "", toolkit.M{}.Set("timeout", 3)})
	if err != nil {
		return
	}

	err = conn.Connect()
	return
}

func TestInitialSetDatabase(t *testing.T) {
	conn, err := prepareconnection()

	if err != nil {
		t.Errorf("Error connecting to database: %s \n", err.Error())
	}

	err = acl.SetDb(conn)
	if err != nil {
		t.Errorf("Error set database to acl: %s \n", err.Error())
	}
}

func TestCreateUser(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 3; i++ {
		initUser := new(acl.User)

		initUser.ID = toolkit.RandomString(32)
		initUser.LoginID = fmt.Sprintf("ACL.LOGINID.%v", i)
		initUser.FullName = fmt.Sprintf("ACL FULLNAME USER.%v", i)
		initUser.Email = fmt.Sprintf("user.%v.sidik@eaciit.com", i)
		initUser.Password = "12345"

		err := acl.Save(initUser)
		if err != nil {
			t.Errorf("Error set initial user to acl: %s \n", err.Error())
		}
	}

	for i := 0; i < 3; i++ {
		iUser := new(acl.User)
		err := acl.FindUserByLoginID(iUser, fmt.Sprintf("ACL.LOGINID.%v", i))
		if err != nil {
			t.Errorf("Error find user by login id: %s \n", err.Error())
			continue
		}
		err = acl.ChangePassword(iUser.ID, "12345")
		if err != nil {
			t.Errorf("Error change password : %s \n", err.Error())
			continue
		}
	}
}

func TestCreateUserLdap(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	initUser := new(acl.User)

	initUser.ID = toolkit.RandomString(32)
	initUser.LoginID = "Alip Sidik"
	initUser.FullName = "Alip Sidik"
	initUser.Email = "alip.sidik@eaciit.com"
	initUser.LoginType = acl.LogTypeLdap
	initUser.LoginConf = toolkit.M{}.Set("address", "192.168.0.200:389")

	err := acl.Save(initUser)
	if err != nil {
		t.Errorf("Error set initial user to acl: %s \n", err.Error())
	}
}

func TestCreateAccess(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 10; i++ {
		initAccess := new(acl.Access)

		initAccess.ID = fmt.Sprintf("ACLTEST.ACCESS.%v", i)
		initAccess.Title = fmt.Sprintf("ACL.APPS.ACCESS.%v", i)
		initAccess.Group1 = ""
		initAccess.Group2 = ""
		initAccess.Group3 = ""
		initAccess.Enable = true
		initAccess.SpecialAccess1 = ""
		initAccess.SpecialAccess2 = ""
		initAccess.SpecialAccess3 = ""
		initAccess.SpecialAccess4 = ""

		err := acl.Save(initAccess)
		if err != nil {
			t.Errorf("Error set initial Access to acl: %s \n", err.Error())
		}
	}
}

func TestCreateGroup(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	for i := 0; i < 4; i++ {
		initGroup := new(acl.Group)

		initGroup.ID = fmt.Sprintf("ACL.GROUP.%v", i)
		initGroup.Title = fmt.Sprintf("ACL.GROUP.TITLE.%v", i)
		initGroup.Enable = true
		initGroup.Grants = nil
		initGroup.Owner = ""

		err := acl.Save(initGroup)
		if err != nil {
			t.Errorf("Error set initial Group to acl: %s \n", err.Error())
		}
	}
}

func TestAddAccesGroup(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")

	tGroup := new(acl.Group)
	err := acl.FindByID(tGroup, "ACL.GROUP.3")

	if err != nil {
		t.Errorf("Error Find By Id in acl: %s \n", err.Error())
	}

	fmt.Printf("Group value from find : %v \n\n", toolkit.JsonString(tGroup))

	tGroup.Grant("ACLTEST.ACCESS.1", acl.AccessCreate+acl.AccessRead+acl.AccessUpdate+acl.AccessDelete)
	tGroup.Grant("ACLTEST.ACCESS.2", acl.AccessCreate, acl.AccessRead)
	tGroup.Grant("ACLTEST.ACCESS.1", acl.AccessRead)

	fmt.Printf("Group after grant : %v \n\n", toolkit.JsonString(tGroup))

	tGroup.Revoke("ACLTEST.ACCESS.1", acl.AccessDelete)
	fmt.Printf("Group after revoke : %v \n\n", toolkit.JsonString(tGroup))

	err = acl.Save(tGroup)
	if err != nil {
		t.Errorf("Error save Group to database: %s \n", err.Error())
	}
}

func TestAddAccesUser(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")

	tUser := new(acl.User)
	err := acl.FindUserByLoginID(tUser, "ACL.LOGINID.1")
	if err != nil {
		t.Errorf("Error Find User By ID ACL: %s \n", err.Error())
	}

	fmt.Printf("User Value : %v \n\n", toolkit.JsonString(tUser))

	tUser.Grant("ACLTEST.ACCESS.2", acl.AccessCreate)
	fmt.Printf("User after grant : %v \n\n", toolkit.JsonString(tUser))

	tUser.AddToGroup("ACL.GROUP.3")
	fmt.Printf("User after add group : %v \n\n", toolkit.JsonString(tUser))

	tUser.Grant("ACLTEST.ACCESS.2", acl.AccessCreate+acl.AccessRead+acl.AccessUpdate+acl.AccessDelete)
	fmt.Printf("User after grant : %v \n\n", toolkit.JsonString(tUser))

	tUser.RemoveFromGroup("ACL.GROUP.3")
	fmt.Printf("User after remove group : %v \n\n", toolkit.JsonString(tUser))

	err = acl.Save(tUser)
	if err != nil {
		t.Errorf("Error save user to database: %s \n", err.Error())
	}
}

func TestFindGenAcl(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	tAccess := new(acl.Access)
	tGroup := new(acl.Group)
	tUser := new(acl.User)

	arrm := make([]toolkit.M, 0, 0)
	c, e := acl.Find(tAccess, nil, toolkit.M{}.Set("take", 3))
	if e == nil {
		e = c.Fetch(&arrm, 0, false)
	}

	if e != nil {
		t.Errorf("Error Found : %v", e.Error())
	} else {
		fmt.Printf("Access : %v \n\n", arrm)
	}

	arrm = make([]toolkit.M, 0, 0)
	c, e = acl.Find(tGroup, nil, toolkit.M{}.Set("take", 1))
	if e == nil {
		e = c.Fetch(&arrm, 0, false)
	}

	if e != nil {
		t.Errorf("Error Found : %v", e.Error())
	} else {
		fmt.Printf("Access : %v \n\n", arrm)
	}

	arrm = make([]toolkit.M, 0, 0)
	c, e = acl.Find(tUser, nil, toolkit.M{}.Set("take", 1))
	if e == nil {
		e = c.Fetch(&arrm, 0, false)
	}

	if e != nil {
		t.Errorf("Error Found : %v", e.Error())
	} else {
		fmt.Printf("Access : %v \n\n", arrm)
	}
	c.Close()
}

func TestFindInAcl(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	tAccess := new(acl.Access)
	tGroup := new(acl.Group)
	tUser := new(acl.User)

	err := acl.FindByID(tAccess, "ACLTEST.ACCESS.1")
	if err != nil {
		t.Errorf("Error Find Access By ID : %s \n", err.Error())
	}
	fmt.Printf("Access value : %v \n\n", toolkit.JsonString(tAccess))

	err = acl.FindByID(tGroup, "ACL.GROUP.1")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("Group value : %v \n\n", toolkit.JsonString(tGroup))

	err = acl.FindUserByLoginID(tUser, "ACL.LOGINID.1")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("User value by login id : %v \n\n", toolkit.JsonString(tUser))

	err = acl.FindUserByEmail(tUser, "user.0.sidik@eaciit.com")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}
	fmt.Printf("User value by email : %v \n\n", toolkit.JsonString(tUser))

	foundcond := acl.HasAccess("ACL.LOGINID.1", acl.IDTypeUser, "ACLTEST.ACCESS.8", acl.AccessCreate+acl.AccessRead)
	fmt.Printf("Found has access 01 : %v \n\n", foundcond)

	foundcond = acl.HasAccess("ACL.GROUP.3", acl.IDTypeGroup, "ACLTEST.ACCESS.2", acl.AccessCreate+acl.AccessRead)
	fmt.Printf("Found has access 02 : %v \n\n", foundcond)
}

func TestDeleteInAcl(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	tAccess := new(acl.Access)
	tGroup := new(acl.Group)
	tUser := new(acl.User)

	err := acl.FindByID(tAccess, "ACLTEST.ACCESS.9")
	if err != nil {
		t.Errorf("Error Find Access By ID : %s \n", err.Error())
	} else {
		err = acl.Delete(tAccess)
		if err != nil {
			t.Errorf("Error delete access : %s \n", err.Error())
		}
	}

	err = acl.FindByID(tGroup, "ACL.GROUP.3")
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	} else {
		err = acl.Delete(tGroup)
		if err != nil {
			t.Errorf("Error delete group : %s \n", err.Error())
		}
	}

	err = acl.FindUserByLoginID(tUser, "ACL.LOGINID.2")
	if err != nil {
		t.Errorf("Error find user by loginid : %s \n", err.Error())
	} else {
		err = acl.Delete(tUser)
		if err != nil {
			t.Errorf("Error delete user : %s \n", err.Error())
		}
	}
}

func TestTokens(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	tUser := new(acl.User)

	err := acl.FindUserByLoginID(tUser, "ACL.LOGINID.1")
	if err != nil {
		t.Errorf("Error Find User By ID ACL: %s \n", err.Error())
		return
	}
	fmt.Printf("FOUND ID : %v \n\n", tUser.ID)

	err = acl.CreateToken(tUser.ID, "ChangePassword", time.Minute*5)
	if err != nil {
		t.Errorf("Create user token found : %s \n", err.Error())
		return
	}
	fmt.Printf("Token created... \n")

	idToken, err := acl.GetToken(tUser.ID, "ChangePassword")
	if err != nil {
		t.Errorf("Get token found : %s \n", err.Error())
		return
	}
	fmt.Printf("Token : %v \n\n", idToken)

	tToken := new(acl.Token)
	err = acl.FindByID(tToken, idToken)
	if err != nil {
		t.Errorf("Error Find Group By ID : %s \n", err.Error())
	}

	<-time.After(time.Second * 10)
	tToken.Claim()
	fmt.Printf("Token claimed... \n")

	idToken, err = acl.GetToken(tUser.ID, "ChangePassword")
	if err != nil {
		t.Errorf("Get token found : %s \n", err.Error())
		return
	}
	fmt.Printf("Token : %v \n\n", idToken)
}

func TestSession(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")
	// acl.SetExpiredDuration(time.Second * 25)

	sessionid, err := acl.Login("ACL.LOGINID.0", "12345")
	if err != nil {
		t.Errorf("Login error: %s \n", err.Error())
		t.Skip()
	}
	fmt.Printf("[%v]Session ID : %v \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), sessionid)

	<-time.After(time.Second * 5)

	tUser, err := acl.FindUserBySessionID(sessionid)
	if err != nil {
		t.Errorf("Find user error: %s \n", err.Error())
		return
	}
	fmt.Printf("[%v]User Found : %v \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), tUser)

	<-time.After(time.Second * 30)

	// err = acl.Logout(sessionid)
	// if err == nil {
	// 	t.Errorf("Logout error: %s \n", "must be expired")
	// } else {
	// 	fmt.Printf("[%v]Session expired : %v \n\n", toolkit.Date2String(time.Now(), "HH:mm:ss"), err.Error())
	// }

	// tUser, err = acl.FindUserBySessionID(sessionid)
	// if err != nil {
	// 	fmt.Printf("[%v]Session Expired : %s \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), err.Error())
	// }
	// fmt.Printf("[%v]User Found : %v \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), tUser)
}

func TestSessionLoginLdap(t *testing.T) {
	t.Skip("Skip : Comment this line to do test")

	sessionid, err := acl.Login("Alip Sidik", "Password.1")
	if err != nil {
		t.Errorf("Login error: %s \n", err.Error())
		t.Skip()
	}
	fmt.Printf("[%v]Session ID : %v \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), sessionid)

	<-time.After(time.Second * 5)

	tUser, err := acl.FindUserBySessionID(sessionid)
	if err != nil {
		t.Errorf("Find user error: %s \n", err.Error())
		return
	}
	fmt.Printf("[%v]User Found : %v \n", toolkit.Date2String(time.Now(), "HH:mm:ss"), tUser)

	<-time.After(time.Second * 30)
}

func TestFindUserLdap(t *testing.T) {
	// t.Skip("Skip : Comment this line to do test")

	addr := "192.168.0.200:389"
	basedn := "DC=eaciit,DC=local"
	filter := "(&(objectclass=person)(objectclass=organizationalPerson)(cn=*id*))"

	param := toolkit.M{}

	param.Set("username", "Alip Sidik")
	param.Set("password", "Password.1")
	param.Set("attributes", []string{"cn", "givenName"})

	arrtkm, err := acl.FindUserLdap(addr, basedn, filter, param)
	if err != nil {
		t.Errorf("Find user ldap error: %s \n", err.Error())
		return
	}

	fmt.Println("User ldap []tkm : ", arrtkm)
}
