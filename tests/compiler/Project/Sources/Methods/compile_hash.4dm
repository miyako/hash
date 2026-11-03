//%attributes = {"invisible":true}
var $parameter : Text
var $ignored : Integer
var $config; $report; $options : Object
$ignored:=Get database parameter(User param value; $parameter)
$config:=JSON Parse(File($parameter).getText())
$options:={targets: New collection("x86_64_generic"; "arm64_macOS_lib"); typeInference: "all"; generateSyntaxFile: True}
If (Value type($config.components)=Is collection)
	$options.components:=New collection
	var $component : Text
	For each ($component; $config.components)
		$options.components.push(File($component))
	End for each
End if
$report:=Compile project(File($config.project); $options)
File($config.report).setText(JSON Stringify($report; *))
If (Application type#6)
	QUIT 4D
End if
