package acl

import (
	"github.com/eaciit/orm/v1"
)

type Group struct {
	orm.ModelBase
	ID     string        `json:"_id",bson:"_id"`
	Title  string        // `json:"Title",bson:"Title"`
	Enable bool          // `json:"Enable",bson:"Enable"`
	Grants []AccessGrant // `json:"Grants",bson:"Grants"`
	Owner  string        // `json:"Owner",bson:"Owner"`
}

func (g *Group) TableName() string {
	return "Acl_Group"
}

func (g *Group) RecordID() interface{} {
	return g.ID
}

func (g *Group) Grant(tAccessID string, tAccessEnum ...AccessTypeEnum) {
	f, i := getgrantindex(g.Grants, tAccessID)
	if f {
		for _, tAE := range tAccessEnum {
			splittAE := splitgrantvalue(tAE)
			for _, iSplittAE := range splittAE {
				if !Matchaccess(iSplittAE, g.Grants[i].AccessValue) {
					g.Grants[i].AccessValue += iSplittAE
				}
			}
		}
	} else {
		sint := 0
		for _, tAE := range tAccessEnum {
			sint += int(tAE)
		}

		if sint == 0 {
			return
		}

		tag := AccessGrant{
			AccessID:    tAccessID,
			AccessValue: sint,
		}

		g.Grants = append(g.Grants, tag)
	}
	return
}

func (g *Group) Revoke(tAccessID string, tAccessEnum ...AccessTypeEnum) {
	f, i := getgrantindex(g.Grants, tAccessID)
	if f {
		for _, tAE := range tAccessEnum {
			splittAE := splitgrantvalue(tAE)
			for _, iSplittAE := range splittAE {
				if Matchaccess(iSplittAE, g.Grants[i].AccessValue) {
					g.Grants[i].AccessValue -= iSplittAE
				}
			}
		}
	}

	if g.Grants[i].AccessValue == 0 {
		g.Grants = append(g.Grants[:i], g.Grants[i+1:]...)
	}

	return
}

func (g *Group) GetAccessList() (arrgrant []AccessGrant) {
	arrgrant = make([]AccessGrant, 0, 0)
	arrgrant = append(arrgrant, g.Grants...)
	return
}
