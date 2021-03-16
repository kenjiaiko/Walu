import sys
t = float(sys.argv[3])
with open(sys.argv[1]) as R, open(sys.argv[2], "w") as W:
	for l in R.readlines():
		try:
			score, data = l.split(" ", 1)
		except:
			continue
		if float(score) < t:
			W.write(data)

