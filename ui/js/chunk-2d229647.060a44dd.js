(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d229647"],{dcf8:function(t,e,a){"use strict";a.r(e);var i=function(){var t=this,e=t.$createElement,a=t._self._c||e;return a("CRow",[t.loading?a("CCol",{attrs:{col:""}},[a("div",{staticStyle:{margin:"auto","text-align":"center","verticle-align":"middle"}},[a("CSpinner",{staticStyle:{width:"6rem",height:"6rem"},attrs:{color:"dark"}})],1)]):a("CCol",{attrs:{col:""}},[a("CAlert",{attrs:{show:t.alert,color:"success",closeButton:""},on:{"update:show":function(e){t.alert=e}}},[t._v(t._s(t.alert_message))]),a("CButton",{attrs:{color:"primary"},on:{click:t.showModal}},[t._v("Upload Plugin")]),a("br"),a("br"),a("CRow",[a("CCol",[a("h2",[t._v("Available Plugins")])])],1),a("CRow",t._l(t.plugins,(function(e){return a("CCol",{key:e.name,attrs:{lg:"4"}},[a("CCard",{staticClass:"shadow-sm bg-white rounded"},[a("CCardBody",[a("div",{staticClass:"text-right"},[a("CSwitch",{attrs:{color:"success","label-on":"On","label-off":"Off",checked:e.enabled}})],1),a("div",{staticClass:"text-center"},[a("img",{staticStyle:{"max-width":"100%","max-height":"200px"},attrs:{src:"data:image/png;base64,"+e.logo}})]),t._v(" "+t._s(e.description)),a("br"),t._v(" Number of actions: "+t._s(e.manifest.actions.length)),a("br")]),a("CCardFooter",[a("CRow",[a("CCol",{staticClass:"text-left"},[a("span",{staticStyle:{"font-size":".85em"}},[a("b",[t._v("Last Updated:")]),t._v(" "+t._s(t._f("moment")(e.modified_at,"from","now"))),a("br"),a("b",[t._v("Configured:")]),t._v(" "+t._s(e.configs.length))])]),a("CCol",{staticClass:"text-right"},[a("CButton",{attrs:{color:"primary",to:e.uuid,size:"sm"}},[t._v("Configure")])],1)],1)],1)],1)],1)})),1)],1),a("CModal",{attrs:{title:"New Plugin",color:"dark",centered:!0,size:"lg",show:t.uploadPluginModal},on:{"update:show":function(e){t.uploadPluginModal=e}},scopedSlots:t._u([{key:"footer",fn:function(){return[a("CButton",{attrs:{color:"danger"},on:{click:function(e){t.uploadPluginModal=!1}}},[t._v("Discard")])]},proxy:!0}])},[a("div",[t.isInitial||t.isSaving?a("form",{attrs:{enctype:"multipart/form-data",novalidate:""},on:{submit:function(e){return e.preventDefault(),t.uploadPlugin(e)}}},[a("p",{staticClass:"text-muted"},[t._v("Upload a new plugin using the upload form below. Plugins must be uploaded in .zip format.")]),a("div",{staticClass:"dropbox"},[a("input",{staticClass:"input-file",attrs:{type:"file",multiple:"",name:t.uploadFieldName,disabled:t.isSaving},on:{change:function(e){t.filesChange(e.target.name,e.target.files),t.fileCount=e.target.files.length}}}),t.isInitial?a("p",[t._v("Drag your plugin files here to begin")]):t._e(),t.isSaving?a("p",[t._v("Uploading "+t._s(t.fileCount)+" plugins")]):t._e()])]):t._e(),t.isSuccess?a("div",[a("h2",[t._v("Uploaded "+t._s(t.uploadedFiles.length)+" file(s) successfully.")]),a("p",[a("a",{attrs:{href:"javascript:void(0)"},on:{click:function(e){return t.reset()}}},[t._v("Upload again")])]),a("ul",t._l(t.uploadedFiles,(function(e){return a("li",{key:e.name},[t._v(t._s(e.name)+" ")])})),0)]):t._e(),t.isFailed?a("div",[a("h2",[t._v("Upload failed.")]),a("p",[a("br"),a("a",{attrs:{href:"javascript:void(0)"},on:{click:function(e){return t.reset()}}},[t._v("Try again")])]),a("pre",[t._v(t._s(t.uploadError))])]):t._e()])])],1)},n=[],s=(a("2f62"),0),o=1,r=2,l=3,u={name:"Inputs",computed:{isInitial:function(){return this.currentStatus===s},isSaving:function(){return this.currentStatus===o},isSuccess:function(){return this.currentStatus===r},isFailed:function(){return this.currentStatus===l}},created:function(){this.loadData(),this.refresh=setInterval(function(){this.loadData()}.bind(this),6e4)},data:function(){return{name:"",description:"",dismissCountDown:10,loading:!0,uploadFieldName:"files",currentStatus:s,uploadError:null,uploadedFiles:[],uploadPluginModal:!1,alert:!1,alert_message:""}},methods:{reset:function(){this.currentStatus=s,this.uploadedFiles=[],this.uploadError=null},showModal:function(){this.reset(),this.uploadPluginModal=!0},save:function(t){var e=this;this.currentStatus=o,this.$store.dispatch("uploadPlugin",t).then((function(t){e.uploadedFiles=[].concat(t),e.currentStatus=r,e.loadData()})).catch((function(t){e.uploadError=t.response.data.message,e.currentStatus=l}))},filesChange:function(t,e){var a=new FormData;e.length&&(Array.from(Array(e.length).keys()).map((function(i){a.append(t,e[i],e[i].name)})),this.save(a))},addSuccess:function(){return"success"==this.$store.getters.addSuccess},loadData:function(){var t=this;this.loading=!0,this.$store.dispatch("getPlugins").then((function(e){t.plugins=e.data,t.loading=!1}))}},beforeDestroy:function(){clearInterval(this.refresh)}},c=u,d=a("2877"),p=Object(d["a"])(c,i,n,!1,null,null,null);e["default"]=p.exports}}]);
//# sourceMappingURL=chunk-2d229647.060a44dd.js.map