# esign-go

[![golang](https://img.shields.io/badge/Language-Go-green.svg?style=flat)](https://golang.org) [![GitHub release](https://img.shields.io/github/release/shenghui0779/esign-go.svg)](https://github.com/shenghui0779/esign-go/releases/latest) [![pkg.go.dev](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/shenghui0779/esign-go) [![Apache 2.0 license](http://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/apache2.0)

E签宝 Go SDK

```sh
go get -u github.com/shenghui0779/esign-go
```

### 签章准备

> 制作合同模板，切记：保存「模板ID」

- 第一步：获取上传URL 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/rlh256)
- 第二步：上传合同模板文件 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/rlh256)
- 第三步：查询文件上传状态 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/qz4aip)
- 第四步：获取制作合同模板的页面 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/xagpot)
- 第五步：查询合同模板控件详情 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/aoq509)

### 签章流程

> 基于合同模板创建签章流程，切记：保存「文件ID」和「流程ID」

- 第一步：填写模板生成文件 👉 [这里](https://open.esign.cn/doc/opendoc/file-and-template3/mv8a3i)
- 第二步：基于文件发起签署 👉 [这里](https://open.esign.cn/doc/opendoc/pdf-sign3/su5g42)
- 第三步：获取签署页面链接 👉 [这里](https://open.esign.cn/doc/opendoc/pdf-sign3/pvfkwd)
- 第四步：处理异步回调通知 👉 [这里](https://open.esign.cn/doc/opendoc/notify3/glqgy1)
