(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d0ccf9c"],{"4fe9":function(t,e,a){"use strict";a.r(e);var o=function(){var t=this,e=t.$createElement,a=t._self._c||e;return a("CRow",[a("CCol",{attrs:{col:""}},[a("CCard",[a("link",{attrs:{rel:"stylesheet",href:"https://unpkg.com/vue-multiselect@2.1.0/dist/vue-multiselect.min.css"}}),a("CCardBody",[a("CForm",{on:{submit:function(e){return e.preventDefault(),t.createPlaybook(e)}}},[a("h1",[t._v("Create Playbook")]),a("p",{staticClass:"text-muted"},[t._v("Fill out the form below to create a new playbook.")]),a("CInput",{attrs:{placeholder:"Playbook Name",required:"",label:"Playbook Name"},model:{value:t.name,callback:function(e){t.name=e},expression:"name"}}),a("CTextarea",{attrs:{placeholder:"Enter a description for the playbook.  The more detail the better.",required:"",label:"Description"},scopedSlots:t._u([{key:"prepend-content",fn:function(){return[a("CIcon",{attrs:{name:"cil-description"}})]},proxy:!0}]),model:{value:t.description,callback:function(e){t.description=e},expression:"description"}}),a("div",{staticClass:"form-group",attrs:{role:"group"}},[a("label",{staticClass:"typo__label"},[t._v("Tags")]),a("multiselect",{attrs:{placeholder:"Select tags to apply to this playbook",taggable:!0,"tag-placeholder":"Add new tag","track-by":"name",label:"name",options:t.tags,multiple:!0},on:{tag:t.addTag},model:{value:t.selected,callback:function(e){t.selected=e},expression:"selected"}})],1),a("CRow",[a("CCol",{staticClass:"text-right",attrs:{col:"12"}},[a("CButton",{staticClass:"px-4",attrs:{color:"primary",type:"submit"}},[t._v("Create")])],1)],1)],1)],1)],1)],1)],1)},s=[],r=a("2f62"),i=(a("4a7a"),{name:"CreatePlaybook",created:function(){this.$store.dispatch("getTags"),this.$store.dispatch("getOrganizations"),this.$store.commit("add_start")},methods:{createPlaybook:function(){var t=this,e=this.name,a=this.description,o=this.url,s=this.organization_uuid["value"];this.$store.dispatch("createPlaybook",{name:e,description:a,url:o,organization_uuid:s}).then((function(e){var a=e.data.uuid;if(t.selected.length>0){var o=t.selected,s={tags:[]};for(var r in o)void 0!==o[r]["name"]?s["tags"].push(o[r]["name"]):s["tags"].push(o[r]);var i={uuid:a,data:s};t.$store.dispatch("addTagsToPlaybook",i)}t.$router.go(-1)}))},formatOrgSelect:function(){var t=[],e=this.organizations;for(var a in e)t.push({value:e[a]["uuid"],label:e[a]["name"]});return t},addTag:function(t){var e={name:t,uuid:"",color:"#ffffff"};this.tags.push(e),this.selected.push(e)}},computed:Object(r["b"])(["tags","organizations"]),data:function(){return{name:"",description:"",url:"",success:!1,errorMessage:"",organization_uuid:"",test:0,selected:""}}}),l=i,n=a("2877"),c=Object(n["a"])(l,o,s,!1,null,null,null);e["default"]=c.exports}}]);
//# sourceMappingURL=chunk-2d0ccf9c.0fc59f8a.js.map