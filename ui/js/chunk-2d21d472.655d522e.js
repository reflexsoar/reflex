(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d21d472"],{d12a:function(t,e,n){"use strict";n.r(e);var r=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("CRow",[t.loading?n("CCol",{attrs:{col:""}},[n("div",{staticStyle:{margin:"auto","text-align":"center","verticle-align":"middle"}},[n("CSpinner",{staticStyle:{width:"6rem",height:"6rem"},attrs:{color:"dark"}})],1)]):n("CCol",{attrs:{col:""}},[n("div",{staticStyle:{padding:"10px"}},[n("CButton",{attrs:{color:"primary",disabled:!t.current_user.permissions.includes("pair_agent")},on:{click:function(e){return t.generateToken()}}},[t._v("New Agent")])],1),n("CDataTable",{staticStyle:{"border-top":"1px solid #cfcfcf"},attrs:{hover:t.hover,striped:t.striped,bordered:t.bordered,small:t.small,fixed:t.fixed,items:t.inputs,fields:t.fields,"items-per-page":t.small?25:10,dark:t.dark,sorter:{external:!0,resetable:!0},pagination:""},scopedSlots:t._u([{key:"name",fn:function(e){var r=e.item;return[n("td",[n("router-link",{attrs:{to:""+r.uuid}},[t._v(t._s(r.name))])],1)]}},{key:"inputs",fn:function(e){var r=e.item;return[n("td",[t._v(" "+t._s(r.inputs.length)+" ")])]}},{key:"roles",fn:function(e){var r=e.item;return[n("td",t._l(r.roles,(function(e){return n("li",{key:e.name,staticStyle:{display:"inline","margin-right":"2px"}},[n("CButton",{attrs:{color:"primary",size:"sm",disabled:""}},[t._v(t._s(e.name))])],1)})),0)]}},{key:"active",fn:function(e){var r=e.item;return[n("td",[n("CButton",{attrs:{color:t.getStatus(r.active),size:"sm",disabled:""}},[t._v(t._s(t._f("getStatusText")(r.active)))])],1)]}},{key:"last_heartbeat",fn:function(e){var r=e.item;return[n("td",[t._v(" "+t._s(t._f("moment")(r.last_heartbeat,"from","now"))+" ")])]}}])})],1),n("CModal",{attrs:{title:"Agent Pairing Token",color:"dark",centered:!0,size:"lg",show:t.pairingModal},on:{"update:show":function(e){t.pairingModal=e}}},[n("div",{staticClass:"text-center"},[n("h4",[t._v("Pairing Token")]),t._v(" Copy the command below to pair a new agent "),n("pre",{staticClass:"text-white bg-dark text-left prewrap",staticStyle:{padding:"10px","border-radius":"5px"}},[t._v('python reflex-agent.py --pair --token "'+t._s(t.pairingToken)+'" --console '+t._s(t.current_url)+" --roles poller,runner")])])])],1)},a=[],i=n("2f62"),s={name:"Agents",props:{items:Array,fields:{type:Array,default:function(){return["name","roles","inputs","ip_address","active","last_heartbeat"]}},caption:{type:String,default:"Table"},hover:Boolean,striped:Boolean,bordered:Boolean,small:Boolean,fixed:Boolean,dark:Boolean,alert:!1},computed:Object(i["b"])(["current_user"]),created:function(){this.current_url=window.location.origin,this.loadData(),this.refresh=setInterval(function(){this.loadData()}.bind(this),6e4)},data:function(){return{name:"",current_url:"",description:"",url:"",pairingModal:!1,pairingToken:"Failed to load pairing token",orgs:Array,dismissCountDown:10,loading:!0}},methods:{addSuccess:function(){return"success"==this.$store.getters.addSuccess},loadData:function(){var t=this;this.loading=!0,this.$store.dispatch("getAgents").then((function(e){t.inputs=e.data,t.loading=!1}))},getStatus:function(t){switch(t){case!0:return"success";case!1:return"danger";default:}},generateToken:function(){var t=this;this.pairingModal=!0,this.$store.dispatch("getPairingToken").then((function(e){t.pairingToken=e.data}))}},filters:{getStatusText:function(t){switch(t){case!0:return"Active";case!1:return"Inactive";default:}}},beforeDestroy:function(){clearInterval(this.refresh)}},o=s,l=n("2877"),d=Object(l["a"])(o,r,a,!1,null,null,null);e["default"]=d.exports}}]);
//# sourceMappingURL=chunk-2d21d472.655d522e.js.map