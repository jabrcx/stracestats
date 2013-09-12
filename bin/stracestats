#!/usr/bin/env python

# Copyright (c) 2012-2013, John A. Brunelle
# All rights reserved.

"""\
NAME
    stracestats - summarize and visualize data in strace output

SYNOPSIS
    stracestats STRACE_OUTPUT_FILE

DESCRIPTION
    This script reads in output from strace and prints out statistics for each 
    system call, such as:

        * occurrences (number of times called, percentage of overall calls 
          made)

        * time spent in the call (total time, percentage of system call time, 
          percentage of wall time)

        * average call time and standard deviation

        * median call time

        * a 10-bin histogram of call times, from min to max

    The results are sorted by the total time spent in each system call.  There 
    are options for plotting the call time histograms, too.

    The STRACE_OUTPUT_FILE must be from an strace run with both timestamps and 
    time-in-call recorded, e.g.:

        strace -tt -T -o STRACE_OUTPUT_FILE ...

    The -t and -ttt alternatives to -tt, for different timestamp formats, are 
    also acceptable.  This works with any combination of -f, -ff and -o, too 
    (i.e. the output may have extra process id info prepended).

    If STRACE_OUTPUT_FILE is not given, this script reads from stdin.

OPTIONS
    --breakdown-by-arg
        Treat calls with different numeric values for their first argument as 
        separate system calls (i.e. record separate statistics for each unique 
        first argument value, rather than one set of statistics for the call 
        overall).

        This is most helpful when the first argument is a file descriptor.  
        E.g. if STRACE_OUTPUT_FILE describes reading from two files with 
        descriptors 3 and 4, this option will print out separate stats for 
        \`read(3' and \`read(4'.

    --show-plots
        Display plots of the statistics (requires matplotlib and an X display). 
        See also --plot.

    --save-plots
        Save plots of the statistics (requires matplotlib and an X display). 
        See also --plot.

    --plot SYSTEM_CALL...
        Specify which system calls to plot when using --show-plots and/or 
        --save-plots.  This should be a space- or comma-separate listed of 
        system call names (including the open parenthesis and first arg, if 
        using --breakdown-by-arg), or one of the following special values:

        * ALL

          Plot all system calls.

        * TOPX, where X is a number

          Plot the X calls in which the most time is spent.

        The default is TOP3.

    --title TITLE
        Add a title to the plots (if applicable) and their filenames (if 
        saved).  The title on the plots will still be appended with the 
        specific system call name and some extra text, and title in the 
        filename will have spaces replaced by underscores.

    -h, --help
        Print this help.

REQUIREMENTS
    python 2.7 or greater
    numpy
    matplotlib (if plotting)

BUGS/TODO
    n/a

AUTHOR
    Copyright (c) 2012-2013, John Brunelle
"""


import sys, getopt, datetime, re, socket

#datetime.timedelta.total_seconds introduced in 2.7
#datetime.strptime introduced in 2.5
if sys.version_info < (2,7):
	msg = "*** ERROR *** this script requires python >= 2.7"
	if socket.gethostname().endswith('.rc.fas.harvard.edu'): msg += " (module load hpc/python-2.7.1_full_stack)"
	sys.stderr.write(msg+'\n')
	sys.exit(1)

try:
	import numpy as np
except ImportError:
	msg = "*** ERROR *** this script requires numpy"
	if socket.gethostname().endswith('.rc.fas.harvard.edu'): msg += " (module load hpc/python-2.7.1_full_stack)"
	sys.stderr.write(msg+'\n')
	sys.exit(1)


breakdown_by_arg = False
show_plots = False
save_plots = False

plot = []
plot_all = False
plot_topx = 0
title = None

debug = False

try:
	opts, args = getopt.gnu_getopt(sys.argv[1:], 'h', ('breakdown-by-arg','show-plots','save-plots','plot=','title=', 'help',))
except getopt.GetoptError, e:
	sys.stderr.write("*** ERROR **** unable to process command line options: %s\n" % e)
	sys.exit(1)
for opt, optarg in opts:
	if opt in ('--breakdown-by-arg',):
		breakdown_by_arg = True

	elif opt=='--show-plots':
		show_plots = True
	elif opt=='--save-plots':
		save_plots = True
	elif opt=='--plot':
		for p in re.split('[ ,]', optarg):
			if p=='':
				continue
			if p=='ALL':
				plot_all = True
				break
			if p.startswith('TOP'):
				try:
					plot_topx = max(plot_topx, int(p.split('TOP')[1]))
				except ValueError:
					sys.stderr.write("*** ERROR *** [%s] in not a valid --plot value\n" % p)
					sys.exit(1)
				#(don't break; allow additional specific plots)
			else:
				plot.append(p)
	elif opt=='--title':
		title = optarg

	elif opt in ('-h', '--help'):
		sys.stdout.write(__doc__)
		sys.exit(0)

plotting = (show_plots or save_plots)

if plotting and len(plot)==0 and not plot_all and plot_topx==0:
	plot_topx=3

if not plotting and (len(plot)>0 or plot_all or plot_topx>0):
	sys.stderr.write("*** ERROR *** when using --plot, you must also provide --show-plots and/or --save-plots\n")
	sys.exit(1)

if plotting:
	try:
		import matplotlib.pyplot as plt
	except ImportError:
		msg = "*** ERROR *** matplotlib is needed for plotting"
		if socket.gethostname().endswith('.rc.fas.harvard.edu'): msg += " (module load hpc/python-2.7.1_full_stack)"
		sys.stderr.write(msg+'\n')
		sys.exit(1)

if len(args)==0:
	args.append('-')


#---


###plan to add options to total and breakdown bytes at some point
##syscalls where the return value is a number of bytes
#syscalls_bytes = set((
#	'read', 'write',
#	'pread', 'pwrite',
#	'recv', 'recvfrom', 'recvmsg',
#	'send', 'sendto'  , 'sendmsg',
#))

#regex for a syscall line
re_entry_general          = re.compile(r'((\[pid +\d+\]|\d+) +)?([\d:\.]+) ([^\(]+)(\(.*\)) += (.+) <([\d\.]+)>')

#regex for an arg string starting with a number (just the number and its surrounding characters)
re_numeric_first_arg = re.compile('^\(\d(,|\))')

syscalls = {}

tstart = None  #wall clock time of first entry
tend   = None  #wall clock time of last entry

parse_time_functions = {
	't'  : lambda s: datetime.datetime.strptime(s, '%H:%M:%S'),
	'tt' : lambda s: datetime.datetime.strptime(s, '%H:%M:%S.%f'),
	'ttt': lambda s: datetime.datetime.fromtimestamp(float(s)),  #(datetime has no format specifier for seconds since epoch (would use something like '%s.%f' if available)
}
best_chance_time_format = 'tt'


#--- collect data

for filename in args:
	if filename=='-':
		f = sys.stdin
	else:
		f = open(filename)

	for line in f.readlines():
		line = line.strip()

		if debug:
			print line


		#parse

		m = re_entry_general.match(line)
		if not m:
			if not (line.startswith('Process ') or line.endswith('<unfinished ...>') or line.endswith('= ?') or '--- SIG' in line or '+++ exited with' in line):
				sys.stderr.write("WARNING: unable to parse line, skipping: %s\n" % line)
			continue
		offset = 2  #helps with indexing as I add regex subgroups

		if debug:
			print '    %s' % (m.groups(None),)

		abststr = m.groups(None)[offset]

		abstd = None
		try:
			abstd = parse_time_functions[best_chance_time_format](abststr)
		except ValueError:
			for format in ['tt', 't', 'ttt']:
				try:
					abstd = parse_time_functions[format](abststr)
					best_change_time_format = format
				except ValueError:
					continue
		if abstd is None:
			sys.stderr.write("WARNING: unable to parse time, skipping: %s\n" % abststr)

		if tstart is None:
			tstart = abstd
		tend = abstd

		syscall = m.groups(None)[1+offset]
		if breakdown_by_arg:
			m2 = re_numeric_first_arg.search(m.groups(None)[2+offset])
			if m2 is not None:
				syscall = '%s(%s' % (syscall, m2.group(0)[1:-1])

		retval = m.groups(None)[3+offset]
		if not retval.isdigit():
			try:
				retvall = retval.split()
				if retvall[1].startswith('E'):
					retval = retvall[1]
				else:
					retval = retvall[0]
			except Exception:
				pass

		try:
			t = float(m.groups(None)[4+offset])
		except ValueError:
			sys.stderr.write("WARNING: unable to parse a time, assuming 0.0s: %s\n" % line)
			t = 0.0


		if debug:
			print '    abst   :', abststr, '(parsed as: %s)' % abstd
			print '    syscall:', syscall
			print '    retval :', retval
			print '    t      :', t
			print


		# store

		try:
			d = syscalls[syscall]
		except KeyError:
			d = {
				#these lists should all be the same size -- one entry for each strace line
				'retval': [],
				't'     : [],
			}
			syscalls[syscall] = d

		d['retval'].append(retval)
		d['t'     ].append(t     )


#--- summarize

##no longer relevant, for now
#for each syscall:
#	total time spent in it
#	number of calls, average call time
#	breakdown of:
#		return value, % of time for each
#		argument    , % of time for each

syscallsumms = []

all_num_calls = 0
all_tot_sys_time = 0.0
all_tot_wall_time = (tend - tstart).total_seconds()

max_tot_time = 0.0

for syscall, d in syscalls.items():
	sd = {}
	sd['syscall'] = syscall

	sd['num calls'] = len(d['t'])
	all_num_calls += sd['num calls']

	sd['tot time'] = np.sum(d['t'])
	all_tot_sys_time += sd['tot time']
	max_tot_time = max(max_tot_time, sd['tot time'])

	sd['avg call time'] = np.average(d['t'])
	sd['std call time'] = np.std(d['t'])
	sd['med call time'] = np.median(d['t'])

	sd['min call time'] = np.min(d['t'])
	sd['max call time'] = np.max(d['t'])

	syscallsumms.append(sd)


#--- print

twidth = len(str(int(max_tot_time))) + 7

syscallsumms = sorted(syscallsumms, key = lambda x: x['tot time'])

for i, sd in enumerate(syscallsumms):
	syscall = sd['syscall']

	print syscall

	k = 'num calls'
	print '\t%13s: %*d  %2d%% of syscalls' % (k, twidth, sd[k], int(round(float(sd[k])/all_num_calls*100)))

	k = 'tot time'
	print '\t%13s: %*.6f  %2d%% of syscall time, %2d%% of wall time' % (k, twidth, sd[k], int(round(sd[k]/all_tot_sys_time*100)), int(round(sd[k]/all_tot_wall_time*100)))

	print '\t%13s: %*.6f' % ('avg call time', twidth, sd['avg call time'])
	print '\t%13s: %*.6f' % (          '+/-', twidth, sd['std call time'])

	k = 'med call time'
	print '\t%13s: %*.6f' % (k, twidth, sd[k])

	hist, hist_bin_edges = np.histogram(syscalls[syscall]['t'], 10)

	print
	print '\t%13s: %*.6f %s %*.6f' % ('min/hist/max', twidth, sd['min call time'], hist, twidth, sd['max call time'])

	if plotting:
		if plot_all or (len(syscallsumms)-i <= plot_topx) or (syscall in plot):
			if len(syscalls[syscall]['t'])==1:
				sys.stderr.write("WARNING: skipping plot of [%s] since there is only one value\n" % syscall)
			else:
				fig = plt.figure()
				ax = fig.gca()
				ax.bar(hist_bin_edges[:-1], hist, width=(hist_bin_edges[-1]-hist_bin_edges[0])/len(hist))
				ax.set_ylim(top=1.1*max(hist))  #(I don't like how the highest bar is flush with the plot top by default)

				if title is not None:
					titletmp = title + '\n'
				else:
					titletmp = ''
				titletmp = '%s%s call time distribution' % (titletmp, syscall)
				fig.suptitle(titletmp)

				ax.set_xlabel('seconds')
				ax.set_ylabel('count')

				if save_plots:
					if title is not None:
						titletmp = '%s.' % title.replace(' ','_')
					else:
						titletmp = ''
					titletmp = '%s%s.png' % (titletmp, syscall.replace('(','-'))
					fig.savefig(titletmp)
					print '\t%13s: %s' % ('saved plot', titletmp)

	print

if show_plots:
	plt.show()
