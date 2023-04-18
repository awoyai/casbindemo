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
	casbin := auth.NewCasbin("root:root@(localhost:3306)/casbin_demo")

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
	g.GET("/role/add", middleFunc, func(ctx *gin.Context) {
		role := ctx.Query("role")
		if err := casbin.AddRole(role); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/role/list", middleFunc, func(ctx *gin.Context) {
		roles := casbin.GetRoles()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": roles})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/policy/list", middleFunc, func(ctx *gin.Context) {
		policies := casbin.GetPolicies()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": policies})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/policy/add", middleFunc, func(ctx *gin.Context) {
		role := ctx.Query("role")
		policy := ctx.QueryArray("policy")
		rules := make([][]string, len(policy))
		for i, v := range policy {
			rules[i] = []string{role, v, "*"}
		}
		roles := casbin.AddPolicies(rules)
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": roles})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/add", middleFunc, func(ctx *gin.Context) {
		username := ctx.Query("username")
		if err := casbin.AddUser([]string{"member"}, username); err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"ret": http.StatusInternalServerError, "msg": "内部服务器错误", "data": make([]string, 0)})
			ctx.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": make([]string, 0)})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.GET("/user/list", middleFunc, func(ctx *gin.Context) {
		users := casbin.GetUsers()
		ctx.JSON(http.StatusOK, gin.H{"ret": 0, "msg": "success", "data": users})
		ctx.AbortWithStatus(http.StatusOK)
	})
	g.Run()
}
