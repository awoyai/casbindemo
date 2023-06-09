package auth

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter/v2"
	_ "github.com/go-sql-driver/mysql"
)

const (
	DefualtDomain    = "main"
	DefaultRole      = "member"
	DefaultSuperRole = "root"
)

type Casbin struct {
	e *casbin.Enforcer
}

func NewCasbin(dns string) *Casbin {
	a, err := xormadapter.NewAdapterWithTableName("mysql", dns, "casbin", "tb_", true)
	if err != nil {
		panic("NewAdapter err: " + err.Error())
	}
	m, err := model.NewModelFromString(`
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act

	[role_definition]
	g = _, _

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act || r.sub != "root" && g(r.sub, "root")
	`)
	if err != nil {
		panic("NewModelFromString err: " + err.Error())
	}

	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		panic("NewEnforcer err: " + err.Error())
	}
	return &Casbin{e: e}
}

func (c *Casbin) CheckPermission(sub, obj, act string) (bool, error) {
	return c.e.Enforce(sub, obj, act)
}

func (c *Casbin) AddRole(role string) error {
	_, err := c.e.AddRoleForUser(DefaultSuperRole, role)
	c.e.SavePolicy()
	return err
}

func (c *Casbin) DelRole(role string) error {
	_, err := c.e.DeleteRole(role)
	return err
}

func (c *Casbin) AddUser(user string) error {
	_, err := c.e.AddRoleForUser(user, DefaultRole, DefualtDomain)
	c.e.SavePolicy()
	return err
}

func (c *Casbin) UserAddRole(user, role string) error {
	_, err := c.e.AddRoleForUser(user, role, DefualtDomain)
	c.e.SavePolicy()
	return err
}

func (c *Casbin) UserDelRole(user, role string) error {
	_, err := c.e.DeleteRoleForUser(user, role, DefualtDomain)
	c.e.SavePolicy()
	return err
}

func (c *Casbin) AddPolicies(rules [][]string) error {
	_, err := c.e.AddPolicies(rules)
	c.e.SavePolicy()
	return err
}

func (c *Casbin) GetRoles() []string {
	return c.e.GetAllRoles()
}

func (c *Casbin) GetPolicies() [][]string {
	return c.e.GetPolicy()
}

func (c *Casbin) GetUsers() []string {
	users, _ := c.e.GetUsersForRole("member")
	return users
}

func (c *Casbin) DelUser(username string) error {
	_, err := c.e.DeleteUser(username)
	return err
}