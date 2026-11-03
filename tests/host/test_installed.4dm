//%attributes = {"invisible":true}
var $parameter : Text
var $ignored : Integer
var $config; $case; $result; $checks; $entry : Object
var $test : cs.hash.hash
var $file : 4D.File
var $blob : Blob
$ignored:=Get database parameter(User param value; $parameter)
$config:=JSON Parse(File($parameter).getText())
$test:=cs.hash.hash.new()
$checks:={success: True; cases: New collection}
For each ($case; $config.cases)
	$file:=File($case.path)
	$result:=$test.sha256($file)
	$entry:={name: $case.name; result: $result; passed: False}
	If ($case.failure=True)
		$entry.passed:=Not($result.success) & ($result.digest="") & ($result.message#"")
	Else
		$entry.passed:=$result.success & ($result.digest=$case.digest) & ($result.algorithm="sha256")
	End if
	$checks.success:=$checks.success & $entry.passed
	$checks.cases.push($entry)
	If ($case.name="same-size")
		TEXT TO BLOB("two"; $blob; UTF8 text without length)
		$file.setContent($blob)
		$result:=$test.sha256($file)
		$entry:={name: "same-size-change"; result: $result; passed: $result.success & ($result.digest=Lowercase(Generate digest($blob; SHA256 digest))) & ($file.size=3)}
		$checks.success:=$checks.success & $entry.passed
		$checks.cases.push($entry)
	End if
End for each
$checks.executable:=$test._executable().path
$checks.resourceLookup:=($checks.executable=$config.expectedExecutable)
$checks.success:=$checks.success & $checks.resourceLookup
File($config.report).setText(JSON Stringify($checks; *))
If (Application type#6)
	QUIT 4D
End if
