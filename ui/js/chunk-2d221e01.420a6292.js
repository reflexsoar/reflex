(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d221e01"],{cbe1:function(t,i,e){"use strict";e.r(i);var a=function(){var t=this,i=t.$createElement,e=t._self._c||i;return e("CRow",[t.loading?e("CCol",{attrs:{col:""}},[e("div",{staticStyle:{margin:"auto","text-align":"center","verticle-align":"middle"}},[e("CSpinner",{staticStyle:{width:"6rem",height:"6rem"},attrs:{color:"dark"}})],1)]):t._e(),t.loading?t._e():e("CCol",{attrs:{col:""}},[e("CCard",{staticClass:"shadow-sm bg-white rounded"},[e("CCardHeader",[e("CRow",[e("CCol",{staticClass:"text-left",attrs:{col:"12",lg:"6",sm:"12"}},[e("h1",[t._v(t._s(t.input.name))])]),e("CCol",{staticClass:"text-right",attrs:{col:"12",lg:"6",sm:"12"},scopedSlots:t._u([{key:"tags",fn:function(i){var e=i.tag;return[t._v(" "+t._s(e.name)+" ")]}}],null,!1,508650290)},t._l(t.input.tags,(function(i){return e("li",{key:i.name,staticStyle:{display:"inline","margin-right":"2px"}},[e("CButton",{attrs:{color:"primary",size:"sm",disabled:""}},[t._v(t._s(i.name))])],1)})),0)],1),e("CRow",[e("CCol",{attrs:{col:"12",lg:"6",sm:"12"}},[t._v(" "+t._s(t.input.description)+" ")])],1)],1),e("CCardBody",[e("CRow",[e("CCol",{attrs:{col:"6"}},[e("b",[t._v("Name: ")]),t._v(" "+t._s(t.input.name)),e("br"),e("b",[t._v("Enabled: ")]),t._v(" True ")]),e("CCol",{attrs:{col:"6"}},[e("b",[t._v("Plugin: ")]),t._v(" Elasticsearch"),e("br"),e("b",[t._v("Date Created: ")]),t._v(t._s(t._f("moment")(t.input.created_at,"LLLL"))),e("br"),e("b",[t._v("Last Updated: ")]),t._v(t._s(t._f("moment")(t.input.modified_at,"from","now"))+" ")])],1)],1)],1),e("CRow",[e("CCol",[e("CCard",{staticClass:"shadow-sm bg-white rounded"},[e("CCardHeader",[e("CRow",[e("CCol",{staticClass:"text-left",attrs:{col:"12",lg:"6",sm:"12"}},[e("b",[t._v("Configuration")])])],1)],1),e("CCardBody",{staticClass:"bg-dark",staticStyle:{overflow:"scroll","min-height":"300px","max-height":"300px"}},[e("CRow",{staticClass:"bg-dark"},[e("CCol",{staticClass:"bg-dark pre-formatted raw_log",attrs:{col:"12"}},[t._v(" "+t._s(t.input.config)+" ")])],1)],1)],1)],1),e("CCol",[e("CCard",{staticClass:"shadow-sm bg-white rounded",on:{mouseover:function(i){t.field_mapping_hover=!0},mouseleave:function(i){t.field_mapping_hover=!1}}},[e("CCardHeader",[e("CRow",[e("CCol",{staticClass:"text-left",attrs:{col:"12",lg:"6",sm:"12"}},[e("b",[t._v("Field Mapping")]),t.field_mapping_hover&&!t.edit_field_mapping?e("a",{on:{click:function(i){t.edit_field_mapping=!t.edit_field_mapping}}},[e("CIcon",{attrs:{name:"cilPencil",size:"sm"}})],1):t._e()])],1)],1),t.edit_field_mapping?t._e():e("CCardBody",{staticClass:"bg-dark",staticStyle:{overflow:"scroll","min-height":"300px","max-height":"300px"}},[e("CRow",{staticClass:"bg-dark"},[e("CCol",{staticClass:"bg-dark pre-formatted raw_log",attrs:{col:"12"}},[t._v(" "+t._s(t.input.field_mapping)+" ")])],1)],1),t.edit_field_mapping?e("CCardBody",{staticClass:"text-right"},[e("CAlert",{staticClass:"text-left",attrs:{show:t.json_error,color:"danger",closeButton:""},on:{"update:show":function(i){t.json_error=i}}},[t._v(" Invalid JSON. Please check your config before submitting. ")]),e("CTextarea",{attrs:{value:t.configToString(),rows:"10"},on:{change:function(i){return t.convertFieldMapping(i)}}}),e("CButton",{attrs:{color:"danger",size:"sm"},on:{click:function(i){t.edit_field_mapping=!t.edit_field_mapping}}},[e("CIcon",{attrs:{name:"cilXCircle"}})],1),t._v(" "),e("CButton",{attrs:{color:"primary",size:"sm",disabled:t.json_error},on:{click:function(i){return t.updateFieldMapping()}}},[e("CIcon",{attrs:{name:"cilSave"}})],1)],1):t._e()],1)],1)],1)],1)],1)},n=[],s=e("2f62"),o={name:"InputDetails",data:function(){return{uuid:this.$route.params.uuid,loading:!0,cardCollapse:!0,collapse:{},toggleCollapse:!0,edit_field_mapping:!1,field_mapping_hover:!1,edit_config:!1,config_hover:!1,json_error:!1}},computed:Object(s["b"])(["input"]),created:function(){var t=this;this.$store.dispatch("getInput",this.$route.params.uuid).then((function(i){t.loading=!1}))},methods:{configToString:function(){return JSON.stringify(this.input.field_mapping,void 0,4)},convertFieldMapping:function(t){try{this.input.field_mapping=JSON.parse(t),this.json_error=!1}catch(i){this.input.field_mapping=this.input.field_mapping,this.json_error=!0}},updateFieldMapping:function(){var t=this,i=this.uuid,e=null;try{e=JSON.parse(JSON.stringify(this.input.field_mapping)),this.json_error=!1}catch(a){e=null,this.json_error=!0}e&&this.$store.dispatch("updateInput",{uuid:i,data:{field_mapping:e}}).then((function(i){t.edit_field_mapping=!1}))},expandAll:function(){for(var t in this.collapse)this.collapse[t]||(this.collapse[t]=!0);this.toggleCollapse=!1},collapseAll:function(){for(var t in this.collapse)this.collapse[t]&&(this.collapse[t]=!1);this.toggleCollapse=!0}},filters:{firstTwo:function(t){return t?(t=t.toString(),t.substring(0,2)):""},capitalize:function(t){return t?(t=t.toString(),t.toUpperCase()):""},truncate:function(t){var i=250;return t?(t=t.toString(),t.length>i?t.substring(0,i)+"...":t.substring(0,i)):""}}},r=o,l=e("2877"),c=Object(l["a"])(r,a,n,!1,null,null,null);i["default"]=c.exports}}]);
//# sourceMappingURL=chunk-2d221e01.420a6292.js.map