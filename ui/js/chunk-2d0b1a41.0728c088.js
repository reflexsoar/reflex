(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d0b1a41"],{"215a":function(e,t,r){"use strict";r.r(t);var a=function(){var e=this,t=e.$createElement,r=e._self._c||t;return r("CRow",[e.loading?r("CCol",{attrs:{col:""}},[r("div",{staticStyle:{margin:"auto","text-align":"center","verticle-align":"middle"}},[r("CSpinner",{staticStyle:{width:"6rem",height:"6rem"},attrs:{color:"dark"}})],1)]):r("CCol",{attrs:{col:""}},[r("CButton",{attrs:{color:"primary",to:"create"}},[e._v("New Organization")]),r("br"),r("br"),r("CCard",[r("CCardHeader",[r("b",[e._v("Organizations")])]),r("CCardBody",[r("CDataTable",{attrs:{hover:e.hover,striped:e.striped,bordered:e.bordered,small:e.small,fixed:e.fixed,items:e.organizations,fields:e.fields,"items-per-page":e.small?25:10,dark:e.dark,sorter:{external:!0,resetable:!0},pagination:""},scopedSlots:e._u([{key:"name",fn:function(t){var a=t.item;return[r("td",[r("router-link",{attrs:{to:""+a.uuid}},[e._v(e._s(a.name))])],1)]}}])})],1)],1)],1)],1)},n=[],o=(r("2f62"),{name:"Organizations",props:{items:Array,fields:{type:Array,default:function(){return["name","description","url","total_projects"]}},caption:{type:String,default:"Table"},hover:Boolean,striped:Boolean,bordered:Boolean,small:Boolean,fixed:Boolean,dark:Boolean,alert:!1},created:function(){var e=this;this.$store.dispatch("getOrganizations").then((function(t){e.organizations=t.data,e.loading=!1}))},data:function(){return{name:"",description:"",url:"",orgs:Array,dismissCountDown:10,loading:!0}},methods:{addSuccess:function(){return"success"==this.$store.getters.addSuccess}}}),i=o,s=r("2877"),l=Object(s["a"])(i,a,n,!1,null,null,null);t["default"]=l.exports}}]);
//# sourceMappingURL=chunk-2d0b1a41.0728c088.js.map