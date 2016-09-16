package acl

var listvalue = []int{1, 2, 4, 8, 16, 32, 64, 128}
var listgrantvalue = []AccessTypeEnum{1, 2, 4, 8, 16, 32, 64, 128}

var mapaccessenum = map[string]AccessTypeEnum{"create": 1, "read": 2, "update": 4,
	"delete": 8, "special1": 16, "special2": 32, "special3": 64, "special4": 128}

func splitgrantvalue(in AccessTypeEnum) []int {
	ain := make([]int, 0, 0)
	for _, i := range listvalue {
		if Matchaccess(i, int(in)) {
			ain = append(ain, i)
		}
	}
	return ain
}

func Splitinttogrant(in int) []AccessTypeEnum {
	ain := make([]AccessTypeEnum, 0, 0)
	for _, i := range listgrantvalue {
		if Matchaccess(int(i), in) {
			ain = append(ain, i)
		}
	}
	return ain
}

func GetAccessEnum(key string) AccessTypeEnum {
	v, k := mapaccessenum[key]
	if k {
		return v
	}
	return 0
}

func Matchaccess(searchAccess int, sourceAccess int) bool {
	if searchAccess == (searchAccess & sourceAccess) {
		return true
	}
	return false
}

func getgrantindex(ag []AccessGrant, AccessID string) (found bool, in int) {
	found = false
	for i, v := range ag {
		if v.AccessID == AccessID {
			in = i
			found = true
			break
		}
	}

	return
}

func getlastpassword(UserId string) (passwd string) {
	passwd = ""

	tUser := new(User)
	err := FindByID(tUser, UserId)
	if err != nil {
		return
	}

	passwd = tUser.Password

	return
}
