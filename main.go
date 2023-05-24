package main

import (
	"github.com/awoyai/casbindemo/auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	g := gin.New()
	g.Use(gin.Logger(), gin.Recovery())
	gin.SetMode(gin.TestMode)
	loader(g)
	g.Run()
}

func loader(g *gin.Engine) {
	casbin := auth.NewCasbin("root:root123@(localhost:3306)/casbin_demo")
	middleFunc := func(ctx *gin.Context) {
		staffname := ctx.GetHeader("staffname")
		url := ctx.Request.URL.Path
		ok, err := casbin.CheckPermission(staffname, url, "*")
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if !ok {
			ctx.JSON(http.StatusForbidden, gin.H{"ret": http.StatusForbidden, "msg": "您当前没有权限进行该操作，请先获取授权", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}
	}
	g.Use(middleFunc)
	g.GET("/role/add", func(ctx *gin.Context) {
		role := ctx.Query("role")
		if err := casbin.AddRole(role); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/role/list", func(ctx *gin.Context) {
		roles := casbin.GetRoles()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": roles})
		ctx.AbortWithStatus(http.StatusOK)
	})

	g.GET("/policy/list", func(ctx *gin.Context) {
		policies := casbin.GetPolicies()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": policies})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/policy/add", func(ctx *gin.Context) {
		role := ctx.Query("role")
		// TODO check role
		policy := ctx.QueryArray("policy")
		rules := make([][]string, len(policy))
		for i, v := range policy {
			rules[i] = []string{role, v, "*"}
		}
		roles := casbin.AddPolicies(rules)
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": roles})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/add", func(ctx *gin.Context) {
		username := ctx.Query("username")
		if err := casbin.AddUser(username); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/role/add", func(ctx *gin.Context) {
		username := ctx.Query("username")
		role := ctx.Query("role")
		// TODO check role
		if err := casbin.UserAddRole(username, role); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/role/del", func(ctx *gin.Context) {
		username := ctx.Query("username")
		role := ctx.Query("role")
		// TODO check role
		if err := casbin.UserDelRole(username, role); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/del", func(ctx *gin.Context) {
		username := ctx.Query("username")
		if err := casbin.DelUser(username); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/list", func(ctx *gin.Context) {
		users := casbin.GetUsers()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": users})
		ctx.AbortWithStatus(http.StatusOK)
	})
}
