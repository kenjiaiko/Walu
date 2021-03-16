for i in range(0x7F - 0x20):
	c = chr(0x20 + i)
	if c.isalnum() == True:
		continue
	print(chr(0x20 + i))
