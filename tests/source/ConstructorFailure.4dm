Class extends hash

property mode : Integer

Class constructor($mode : Integer)
	This.mode:=$mode

Function _newWorker($command : Text; $options : Object)->$worker : 4D.SystemWorker
	Case of
		: (This.mode=1)
			$worker:=4D.SystemWorker.new("/bin/echo"; {currentDirectory: Folder("/no-such-directory")})
		: (This.mode=2)
			$worker:=4D.SystemWorker.new("/bin/echo"; {onResponse: 12})
		: (This.mode=3)
			$worker:=4D.SystemWorker.new("")
	End case
