//%attributes = {"invisible":true}
var $frame : Object
var $errors : Collection
$frame:=hash_errorFrames[hash_errorFrames.length-1]
$errors:=Last errors
$frame.errors.combine($errors)
