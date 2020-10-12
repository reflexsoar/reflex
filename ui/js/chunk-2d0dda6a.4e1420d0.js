(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d0dda6a"],{"81fa":function(t,e,o){"use strict";o.r(e);var n=function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("CRow",[t.loading?o("CCol",{attrs:{col:""}},[o("div",{staticStyle:{margin:"auto","text-align":"center","verticle-align":"middle"}},[o("CSpinner",{staticStyle:{width:"6rem",height:"6rem"},attrs:{color:"dark"}})],1)]):o("CCol",{attrs:{col:""}},[o("div",{staticStyle:{padding:"10px"}},[o("CButton",{attrs:{color:"primary"},on:{click:function(e){return t.newAgentGroup()}}},[t._v("New Agent Group")])],1),o("CDataTable",{staticStyle:{"border-top":"1px solid #cfcfcf"},attrs:{hover:t.hover,striped:t.striped,bordered:t.bordered,small:t.small,fixed:t.fixed,items:t.agent_groups,fields:t.fields,"items-per-page":t.small?25:10,dark:t.dark,sorter:{external:!0,resetable:!0}},scopedSlots:t._u([{key:"name",fn:function(e){var n=e.item;return[o("td",[t._v(" "+t._s(n.name)+" ")])]}},{key:"actions",fn:function(e){var n=e.item;return[o("td",[o("CButton",{attrs:{color:"secondary",size:"sm"},on:{click:function(e){return t.editAgentGroup(n.uuid)}}},[o("CIcon",{attrs:{name:"cilPencil"}})],1)],1)]}}])})],1),o("CModal",{attrs:{title:t.modal_title,color:"dark",centered:!0,size:"lg",show:t.agentGroupModal},on:{"update:show":function(e){t.agentGroupModal=e}},scopedSlots:t._u([{key:"footer",fn:function(){return[o("CButton",{attrs:{color:"danger"},on:{click:function(e){t.agentGroupModal=!1}}},[t._v("Discard")]),o("CButton",{staticClass:"px-4",attrs:{type:"submit",color:"primary"},on:{click:t.modal_action}},[t._v(t._s(t.modal_button_text))])]},proxy:!0}])},[o("div",[o("CForm",{on:{submit:function(e){return e.preventDefault(),t.modal_action(e)}}},[o("p",{staticClass:"text-muted"},[t._v("Fill out the form below to create a new agent group. Agent Groups allow you to group agents into collections that plugins can use to target certain agents.")]),o("CInput",{attrs:{placeholder:"Group Name",required:"",label:"Group Name"},model:{value:t.name,callback:function(e){t.name=e},expression:"name"}}),o("CTextarea",{attrs:{placeholder:"Enter a description for the input.  The more detail the better.",required:"",label:"Description",rows:"5"},model:{value:t.description,callback:function(e){t.description=e},expression:"description"}}),o("CRow",[o("CCol",{staticClass:"text-right",attrs:{col:"12"}})],1)],1)],1)])],1)},a=[],r=o("2f62"),i={name:"AgentGroups",props:{items:Array,fields:{type:Array,default:function(){return["name","description","agent_count","actions"]}},caption:{type:String,default:"Table"},hover:Boolean,striped:Boolean,bordered:Boolean,small:Boolean,fixed:Boolean,dark:Boolean,alert:!1},computed:Object(r["b"])(["agent_group","agent_groups"]),created:function(){this.loadData()},data:function(){return{name:"",description:"",url:"",agentGroupModal:!1,dismissCountDown:10,loading:!0,modal_title:"New Agent Group",modal_action:this.createAgentGroup,modal_button_text:"Create",target_agent_group:"",pagination:{}}},methods:{newAgentGroup:function(){this.modal_title="New Agent Group",this.modal_action=this.createAgentGroup,this.modal_button_text="Create",this.name="",this.description="",this.agentGroupModal=!0},createAgentGroup:function(){var t=this,e=this.name,o=this.description;this.$store.dispatch("createAgentGroup",{name:e,description:o}).then((function(e){t.agentGroupModal=!1}))},updateAgentGroup:function(){var t=this;console.log(this.name,this.description,this.target_agent_group);var e=this.target_agent_group,o={name:this.name,description:this.description};this.$store.dispatch("updateAgentGroup",{uuid:e,data:o}).then((function(e){t.agentGroupModal=!1}))},editAgentGroup:function(t){var e=this;this.$store.dispatch("getAgentGroup",t).then((function(o){e.modal_title="Edit Agent Group",e.modal_action=e.updateAgentGroup,e.modal_button_text="Edit",e.name=e.agent_group.name,e.description=e.agent_group.description,e.target_agent_group=t,e.agentGroupModal=!0}))},addSuccess:function(){return"success"==this.$store.getters.addSuccess},loadData:function(){var t=this;this.loading=!0,this.$store.dispatch("getAgentGroups").then((function(e){t.pagination=e.data.pagination,t.loading=!1}))},getStatus:function(t){switch(t){case!0:return"success";case!1:return"danger";default:}}},filters:{getStatusText:function(t){switch(t){case!0:return"Active";case!1:return"Inactive";default:}}}},s=i,u=o("2877"),c=Object(u["a"])(s,n,a,!1,null,null,null);e["default"]=c.exports}}]);
//# sourceMappingURL=chunk-2d0dda6a.4e1420d0.js.map