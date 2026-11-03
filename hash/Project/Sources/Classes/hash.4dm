Function sha256($file : 4D.File; $options : Object)->$result : Object
	var $timeout : Real
	$timeout:=300
	$result:=This._result()
	If ($file=Null)
		$result.code:="invalid_file"
		$result.message:="sha256 requires a 4D.File."
		return $result
	End if
	If ($options#Null)
		If (Value type($options.timeout)#Is undefined)
			If (Value type($options.timeout)#Is real)
				$result.code:="invalid_timeout"
				$result.message:="options.timeout must be a positive number of seconds."
				return $result
			End if
			$timeout:=$options.timeout
			If (Not(($timeout>0) & ($timeout<=86400)))
				$result.code:="invalid_timeout"
				$result.message:="options.timeout must be greater than zero and at most 86400 seconds."
				return $result
			End if
		End if
	End if
	var $executable : 4D.File
	var $probeTimeout : Real
	$executable:=This._executable()
	If (Is Windows)
		$probeTimeout:=$timeout
		If ($probeTimeout>2)
			$probeTimeout:=2
		End if
		$result:=This._invoke($executable; ""; $probeTimeout; " --architecture")
		If (Not($result.success))
			return $result
		End if
		Case of
			: ($result.stdout="arm64\n")
				$executable:=$executable.parent.parent.file("WindowsARM/hash.exe")
			: ($result.stdout#"amd64\n")
				$result.success:=False
				$result.code:="malformed_architecture"
				$result.message:="Bundled executable returned an invalid architecture."
				return $result
		End case
	End if
	var $path : Text
	If (Is Windows)
		$path:=$file.platformPath
	Else
		$path:=File($file.platformPath; fk platform path).path
	End if
	return This._run($executable; JSON Stringify({path: $path}); $timeout)

Function _result()->$result : Object
	$result:={success: False; digest: ""; algorithm: "sha256"; message: ""; code: ""; stderr: ""; stdout: ""; timedOut: False; errors: New collection}

Function _executable()->$file : 4D.File
	var $folder : 4D.Folder
	$folder:=Folder(Get 4D folder(Current resources folder); fk platform path)
	Case of
		: (Is macOS)
			$file:=$folder.file("bin/macOS/hash")
		: (Is Windows)
			$file:=$folder.file("bin/Windows/hash.exe")
	End case

Function _run($executable : 4D.File; $request : Text; $timeout : Real)->$result : Object
	$result:=This._invoke($executable; $request; $timeout; "")
	If ($result.success)
		If (This._validOutput($result.stdout))
			$result.digest:=Substring($result.stdout; 1; 64)
		Else
			$result.success:=False
			$result.code:="malformed_output"
			$result.message:="SHA-256 executable returned an invalid digest."
		End if
	End if
	return $result

Function _invoke($executable : 4D.File; $request : Text; $timeout : Real; $argument : Text)->$result : Object
	var $worker : 4D.SystemWorker
	var $previousHandler; $command : Text
	var $frame : Object
	var $caughtErrors : Boolean
	var hash_errorFrames : Collection
	$result:=This._result()
	If ($executable=Null)
		$result.code:="unsupported_platform"
		$result.message:="This platform is not supported."
		return $result
	End if
	$result.executable:=$executable.platformPath
	If (Not($executable.exists))
		$result.code:="missing_executable"
		$result.message:="Bundled SHA-256 executable is missing: "+$executable.platformPath
		return $result
	End if
	$command:=Replace string($executable.path; "\\"; "\\\\"; *)
	$command:=Replace string($command; "\""; "\\\""; *)
	$command:="\""+$command+"\""+$argument
	If (hash_errorFrames=Null)
		hash_errorFrames:=New collection
	End if
	$frame:={errors: New collection; stage: "constructor"}
	hash_errorFrames.push($frame)
	$previousHandler:=Method called on error
	ON ERR CALL("hash_onError")
	$worker:=This._newWorker($command; {dataType: "text"; encoding: "UTF-8"; hideWindow: True; timeout: $timeout+2})
	If ($frame.errors.length=0)
		If ($worker#Null)
			$frame.stage:="input"
			$worker.postMessage($request)
			$worker.closeInput()
			If ($frame.errors.length=0)
				$frame.stage:="wait"
				$worker.wait($timeout)
				If (Not($worker.terminated))
					$result.timedOut:=True
					$worker.terminate()
					$worker.wait(2)
				End if
			End if
		End if
	End if
	If ($worker#Null)
		If ($frame.errors.length>0)
			$worker.terminate()
			$worker.wait(2)
		End if
	End if
	ON ERR CALL($previousHandler)
	hash_errorFrames.pop()
	$caughtErrors:=($frame.errors.length>0)
	$result.errors:=$frame.errors
	If ($worker#Null)
		If (Value type($worker.response)=Is text)
			$result.stdout:=$worker.response
		End if
		If (Value type($worker.responseError)=Is text)
			$result.stderr:=$worker.responseError
		End if
		$result.exitCode:=$worker.exitCode
		If (Value type($worker.errors)=Is collection)
			$result.errors.combine($worker.errors)
		End if
	End if
	If ($caughtErrors)
		$result.code:=$frame.stage+"_error"
		$result.message:=JSON Stringify($frame.errors)+$result.stderr
		return $result
	End if
	If ($worker=Null)
		$result.code:="constructor_error"
		$result.message:="4D.SystemWorker.new returned Null."
		return $result
	End if
	Case of
		: ($result.timedOut)
			$result.code:="timeout"
			$result.message:="SHA-256 deadline exceeded."
		: ($result.errors.length>0)
			$result.code:="worker_error"
			$result.message:=JSON Stringify($result.errors)
		: (Value type($worker.exitCode)=Is undefined)
			$result.code:="abnormal_exit"
			$result.message:="SHA-256 executable did not exit normally."
		: ($worker.exitCode#0)
			$result.code:="process_failed"
			$result.message:=$result.stderr
			If ($result.message="")
				$result.message:="SHA-256 executable returned a nonzero exit code."
			End if
		Else
			$result.success:=True
	End case
	If (($result.stderr#"") & ($result.message#$result.stderr))
		$result.message+=$result.stderr
	End if
	return $result

Function _newWorker($command : Text; $options : Object)->$worker : 4D.SystemWorker
	$worker:=4D.SystemWorker.new($command; $options)

Function _validOutput($output : Text)->$valid : Boolean
	var $i; $code : Integer
	$valid:=False
	If (Length($output)#65)
		return $valid
	End if
	If (Character code(Substring($output; 65; 1))#10)
		return $valid
	End if
	For ($i; 1; 64)
		$code:=Character code(Substring($output; $i; 1))
		If (Not((($code>=48) & ($code<=57)) | (($code>=97) & ($code<=102))))
			return $valid
		End if
	End for
	$valid:=True
