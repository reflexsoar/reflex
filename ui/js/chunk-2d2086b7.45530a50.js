(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d2086b7"],{a55b:function(t,e,o){"use strict";o.r(e);var r=function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("CContainer",{staticClass:"d-flex content-center min-vh-100"},[o("CRow",[o("CCol",[0==t.authStatus()?o("CAlert",{attrs:{closeButton:"",color:"danger",fade:""}},[t._v(" Failed to login. Invalid username or password. ")]):t._e(),o("CCardGroup",[o("CCard",{attrs:{color:"light"}},[o("CCardBody",[o("CForm",{on:{submit:function(e){return e.preventDefault(),t.login(e)}}},[o("h1",[t._v("Login")]),o("p",{staticClass:"text-muted"},[t._v("Sign In to your account")]),o("CInput",{attrs:{placeholder:"Email",autocomplete:"username email",required:""},scopedSlots:t._u([{key:"prepend-content",fn:function(){return[o("CIcon",{attrs:{name:"cil-user"}})]},proxy:!0}]),model:{value:t.username,callback:function(e){t.username=e},expression:"username"}}),o("CInput",{attrs:{placeholder:"Password",type:"password",autocomplete:"current-password",required:""},scopedSlots:t._u([{key:"prepend-content",fn:function(){return[o("CIcon",{attrs:{name:"cil-lock-locked"}})]},proxy:!0}]),model:{value:t.password,callback:function(e){t.password=e},expression:"password"}}),o("CRow",[o("CCol",{staticClass:"text-left",attrs:{col:"6"}},[o("CButton",{staticClass:"px-4",attrs:{color:"primary",type:"submit"}},[t._v("Login")])],1),o("CCol",{staticClass:"text-right",attrs:{col:"6"}},[o("CButton",{attrs:{color:"secondary"}},[t._v("Forgot password?")])],1)],1)],1)],1)],1),o("CCard",{staticClass:"text-center py-5 d-sm-down-none",attrs:{color:"muted","text-color":"dark","body-wrapper":""}},[o("h1",{staticStyle:{"font-size":"5em"}},[t._v("re"),o("span",{staticClass:"text-info"},[t._v("flex")])]),o("p",[t._v("Welcome to Reflex, your Security Orchestration, Automation and Response Platform. To get started, log in to the left. ")])])],1)],1)],1)],1)},s=[],n={name:"Login",data:function(){return{username:"",password:""}},methods:{login:function(){var t=this,e=this.username,o=this.password;this.$store.dispatch("login",{username:e,password:o}).then((function(){return t.$router.push("/")})).catch((function(t){return console.log(t)}))},authStatus:function(){if("error"==this.$store.getters.authStatus)return!1}}},a=n,l=o("2877"),u=Object(l["a"])(a,r,s,!1,null,null,null);e["default"]=u.exports}}]);
//# sourceMappingURL=chunk-2d2086b7.45530a50.js.map