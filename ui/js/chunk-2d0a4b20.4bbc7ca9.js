(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d0a4b20"],{"0813":function(t,o,e){"use strict";e.r(o);var s=function(){var t=this,o=t.$createElement,e=t._self._c||o;return e("CContainer",{staticClass:"d-flex content-center min-vh-100"},[e("CRow",[e("CCol",[0==t.authStatus()?e("CAlert",{attrs:{closeButton:"",color:"danger",fade:""}},[t._v(" Failed to change password. ")]):t._e(),e("CCard",{attrs:{color:"light"}},[e("CCardBody",[e("CForm",{on:{submit:function(o){return o.preventDefault(),t.login(o)}}},[e("h1",[t._v("Reset Password")]),e("p",{staticClass:"text-muted"},[t._v("Enter your new password.")]),e("CInput",{attrs:{placeholder:"Password",type:"password",autocomplete:"current-password",required:""},scopedSlots:t._u([{key:"prepend-content",fn:function(){return[e("CIcon",{attrs:{name:"cil-lock-locked"}})]},proxy:!0}]),model:{value:t.password,callback:function(o){t.password=o},expression:"password"}}),e("CInput",{attrs:{placeholder:"Confirm",type:"password",autocomplete:"current-password",required:""},scopedSlots:t._u([{key:"prepend-content",fn:function(){return[e("CIcon",{attrs:{name:"cil-lock-locked"}})]},proxy:!0}]),model:{value:t.confirm_password,callback:function(o){t.confirm_password=o},expression:"confirm_password"}}),e("CRow",[e("CCol",{staticClass:"text-left",attrs:{col:"12"}},[e("CButton",{staticClass:"px-4",attrs:{color:"primary",type:"submit"}},[t._v("Reset Password")])],1)],1)],1),t._v(" "+t._s(t.token)+" ")],1)],1)],1)],1)],1)},r=[],n={name:"ResetPassword",data:function(){return{password:"",confirm_password:"",token:this.$route.params.token}},methods:{login:function(){var t=this,o=this.token,e=this.password;this.$store.dispatch("resetPassword",{token:o,data:{password:e}}).then((function(){return t.$router.push("/")})).catch((function(t){return console.log(t)}))},authStatus:function(){if("error"==this.$store.getters.authStatus)return!1}}},a=n,c=e("2877"),u=Object(c["a"])(a,s,r,!1,null,null,null);o["default"]=u.exports}}]);
//# sourceMappingURL=chunk-2d0a4b20.4bbc7ca9.js.map