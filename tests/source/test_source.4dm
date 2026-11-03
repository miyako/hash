//%attributes = {"invisible":true}
var $parameter : Text
var $ignored : Integer
var $config; $test; $result; $checks; $failure : Object
var $valid; $invalid; $hang; $nonzero : 4D.File
$ignored:=Get database parameter(User param value; $parameter)
$config:=JSON Parse(File($parameter).getText())
$test:=cs.hash.new()
$checks:={}
$checks.lowercase:=$test._validOutput("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")
$checks.uppercase:=Not($test._validOutput("0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\n"))
$checks.extra:=Not($test._validOutput("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n"))
$checks.empty:=Not($test._validOutput(""))
$checks.nullFile:=Not($test.sha256(Null).success)
$checks.badTimeout:=Not($test.sha256(File("/RESOURCES/absent"); {timeout: 0}).success)
$checks.textTimeout:=Not($test.sha256(File("/RESOURCES/absent"); {timeout: "1"}).success)
$checks.missingExecutable:=Not($test._run(File("/RESOURCES/no-such-executable"); "{}"; 1).success)
var $mode : Integer
$checks.constructor:=True
$checks.constructorResults:=New collection
For ($mode; 1; 3)
	$result:=cs.ConstructorFailure.new($mode).sha256(File("/RESOURCES/no-such-file"); {timeout: 1})
	$checks.constructor:=$checks.constructor & ($result.success=False) & ($result.code="constructor_error")
	If ($mode<3)
		$checks.constructor:=$checks.constructor & ($result.errors.length>0)
	End if
	$checks.constructorResults.push($result)
End for
$result:=$test._run(File("/bin/sleep"); "ignored"; 0.1)
$checks.nonzero:=Not($result.success)
$result:=$test._invoke(File("/bin/sleep"); ""; 0.1; " 5")
$checks.timeout:=($result.success=False) & $result.timedOut & ($result.code="timeout")
$checks.timeoutResult:=$result
$result:=$test._run(File("/bin/echo"); ""; 1)
$checks.malformed:=($result.success=False) & ($result.code="malformed_output")
$checks.malformedResult:=$result
$checks.success:=$checks.lowercase & $checks.uppercase & $checks.extra & $checks.empty & $checks.nullFile & $checks.badTimeout & $checks.textTimeout & $checks.missingExecutable & $checks.constructor & $checks.nonzero & $checks.timeout & $checks.malformed
File($config.report).setText(JSON Stringify($checks; *))
If (Application type#6)
	QUIT 4D
End if
