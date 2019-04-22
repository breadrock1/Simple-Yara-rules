import "pe"

private rule isPE {
	condition:
		uint16(0) == 0x5a4d and
		uint16(uint16(0x3c)) == 0x4550
}

rule signature_rule1 : BBSRAT {
	meta:
		hash0 = "58a264b15d33f85157c6eb8cd34e3869"
		hash1 = "74a41c62d9ec1164af82b802da3e8b3e"
	strings:
		$s0 = "Cookie: %08X-%04X-%04X-%02X%02X%02X%02X" fullword ascii
		$s1 = "/bbs/%X/forum.php?sid=%X" fullword ascii
		$s2 = "Global\\GlobalAcProtectMutex" fullword ascii
		$s3 = "ping -n 1 -r 9 www.microsoft.com" fullword ascii
		$s4 = "rundll32.exe \"%s\",Enter" fullword wide
		$s5 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" fullword ascii
	condition:
		isPE and filesize < 200KB and
		( 
		  2 of ($s*) or
		  pe.imphash() == "50fdc8a04d12ce1d8e2e856dad298184" or 
		  pe.exports("Enter")
		)
}

rule signature_rule2 : KeyLogger {
	meta:
		hash0 = "f0cb1cbbe1a705dc716515bf145f8582"
		hash1 = "fa9ffe70e8b5b28b170feba8874c1f94"
		hash2 = "76527df1a338aa2429b286fe9a9c0d48"
	strings:
		$s0 = {8A 1C 10 80 C3 ?? 88 1C 10 40 3B C1}
		$s1 = "AutoStart.dll" fullword ascii
	condition:
		isPE and filesize < 80KB and
		( 
		  any of ($s*) or
		  pe.imphash() == "87c0951e285881bd43cba66d131a379e" or
		  pe.exports("AutoStart")
		)
}

rule signature_rule3 : BackDoor {
	meta:
		hash0 = "fc28edc60eefd03003ec2075542fd8c2"
		hash1 = "559d77361f077500ce684b463844388c"
		hash2 = "5dc37040e59fe4e446ea34bc7cec4a69"
		hash3 = "bcc7556e0ec853b16b8f569580fc4932"
		hash4 = "cebe051a7e05220072336af07a95dd43"
		
	strings:
		$s0 = "%s%04d/%s" fullword ascii
		$s1 = "cmd.exe /c " fullword ascii
		$s2 = "\\foundin.info" fullword ascii
		$s3 = {5C 66 6F 75 6E 64 69 6E  2E 69 6E 66 6F}
	condition:
		 isPE and filesize < 80KB and
		 (
		   2  of ($s*) or 
		   pe.imphash() == "1ba2100264a82d48ed1b5092c86138a8" 
		  )
}

rule signature_rule4 : MSOProtect { 
	meta:
		hash0 = "65c3d6d786c192d4e5d6d717a37b47e3"
		hash1 = "6ab27f668622fc14a57fc70b72b95943"
	strings:
		$s0 = "MSOProtect" fullword ascii
		$s1 = "AllocateAndGetTcpExTableFromStack" fullword ascii
		$s2 = /([0-9]{1,3}[\.]){3}[0-9]{1,3}/		//thanks Pasha
		$s3 = /([A-Z0-9]{11}-[A-Z0-9]{10})/
	condition:
		 isPE and filesize < 40KB and
		 (
		   2 of ($s*) or
		   pe.exports ("MSOProtect")
		  )
}

rule signature_rule5 : Trojan {
	meta:
		hash0 = "73e19be90e0cbc1d23eae4eb3c7f00db"
strings:
		$s0 = "%ALLUSERSPROFILE%\\SSONSVR\\ssonsvr.exe" fullword wide
		$s1 = "%SystemRoot%\\System32\\msiexec.exe" fullword ascii	
		$s2 = "ssonsvr.exe" fullword wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" fullword wide
	condition:
		 isPE and filesize < 40KB and
		 (
		   2 of ($s*) or 
		   pe.imphash() == "509ceb8c75bb9885649973ce5dfcec47" 
		  )	
}

rule signature_rule6 : Exploit {
	meta:
		hash0 = "b3a2352acae5a4ec2028cf6df07cd33b"
		hash1 = "fb6af5a81c0e1d9f91c90846733ac40f"
	strings:
		$s0 = "\\Microsoft\\Office\\offcln.log" fullword ascii
	condition:
		 isPE and filesize < 80KB and any of ($s*)
}

rule signature_rule7 : Generic {
	meta:
		hash0 = "3c6984e0a3c60135e51039521a528858"
	strings:
		$s0 = "proxyinfo.tmp" fullword ascii
		$s1 = "Proxy-Connection: Keep-Alive" fullword ascii
		$s2 = /([0-9]{1,3}[\.]){3}[0-9]{1,3}/		//thanks Pasha!
		$s3 = "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*" fullword ascii	
		$s4 = "Proxy-Authorization: Basic" fullword
	condition:
		 isPE and filesize < 40KB and 2 of ($s*)
}
