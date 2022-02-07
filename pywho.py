#!/usr/bin/env python3

################################################################################
# PY-WHO!? pzs-ng's sitewho ported to Python                                   #
################################################################################
# Uses SHM and glftpd's 'ONLINE' C struct, module sysv_ipc is required         #
# See README and comments in pywho.conf for install and config instructions    #
################################################################################
VERSION = "220207"                                                       # slv #
################################################################################

import string
import struct
import re
import time
import datetime
import configparser
import os
import sys
import socket
import calendar
import collections
import signal
import select
import fcntl
import sysv_ipc

# vars used like #ifdef's in orig sitewho.c
_WITH_ALTWHO = True
_WITH_SS5 = False
_WITH_GEOIP = False
_WITH_SPY = False
_WITH_XXL = False

SCRIPT = os.path.basename(sys.argv[0])
SCRIPTDIR= os.path.dirname(os.path.realpath((sys.argv[0])))
SCRIPTNAME = os.path.splitext(SCRIPT)[0]

if not _WITH_SS5:
  raw_output = 0
  user_idx = 1
else:
  raw_output = 2
  user_idx = 2
uploads = downloads = 0
total_up_speed = total_dn_speed = 0
onlineusers = browsers = idlers = 0
showall = 0
geoip2_buf = {}
geoip2_client = None
geoip2_shown_ex = 0
gl_nocolor = 0
spy_mode = 0
xxl_mode = 0


# handle args

if '-h' in sys.argv or '--help' in sys.argv:
    print(f'./{SCRIPTNAME} [--raw|-ss5|--nbw|--spy] [username]')
    sys.exit(0)
elif '-v' in sys.argv or '--version' in sys.argv:
    ver = f"pypwho-{VERSION}"
    if _WITH_ALTWHO:
      ver += '-altwho'
    if _WITH_GEOIP:
      ver += '-geoip'
    if _WITH_SPY:
      ver += '-spy'
    if _WITH_XXL:
      ver += '-xxl'
    print (ver)
    sys.exit(0)
elif len(sys.argv) > 1 and len(sys.argv[1]) == 5:
  if '--raw' in sys.argv:
    user_idx, raw_output = 2, 1
  elif '--ss5' in sys.argv:
    user_idx, raw_output = 2, 2
  elif '--nbw' in sys.argv:
    user_idx, raw_output = 2, 3
  elif '--spy' in sys.argv:
    user_idx, raw_output = 0, 0
    spy_mode = 1
  elif '--xxl' in sys.argv:
    user_idx, raw_output = 2, 0
    xxl_mode = 1
else:
  if len(sys.argv) > 1 and sys.argv[1][0] == '-':
      print("Error: invalid option, try '-h'")
      print()
      sys.exit(1)


# config file
##############

CONFIGFILE = "{}/{}.conf".format(SCRIPTDIR, SCRIPTNAME)
config = configparser.ConfigParser()
err = []
for cfg in set([ CONFIGFILE, f'{SCRIPTDIR}/pywho.conf' ]):
  try:
    with open(cfg, 'r') as f:
      config.read_string("[DEFAULT]\n" + f.read())
  except Exception as e:
    err.append(e)
if len(err) > 0:
  for i in err:
    print(i)
  print('Error: opening config file')
  sys.exit(1)

layout = {}
default = {}
default['header'] = f".-[PY-WHO]--------------------------------------------------------------."
default['footer'] = f"`------------------------------------------------------------[PY-WHO]---'"
default['separator'] = f" -----------------------------------------------------------------------"
tmpl_str = {}
tmpl_sub = {}
tmpl_sub['space'] = ' '
tmpl_sub['percent'] = '%'
tls_mode = []
tls_mode.insert(0, 'None')      #no ssl
tls_mode.insert(1, 'Control')   #ssl on control
tls_mode.insert(2, 'Both')      #ssl on control and data

try:
  glrootpath = config['DEFAULT']['glrootpath']
  headerfile = config['DEFAULT']['headerfile']
  footerfile = config['DEFAULT']['footerfile']
  separatorfile = config['DEFAULT']['separatorfile']
  husers = config.get('DEFAULT', 'hiddenusers', fallback='')
  hgroups = config.get('DEFAULT', 'hiddengroups', fallback='')
  mpaths = config.get('DEFAULT', 'maskeddirectories', fallback='')
  ipc_key = config.get('DEFAULT', 'ipc_key', fallback='')
  seeallflags = config.get('DEFAULT', 'seeallflags', fallback='')
  maxusers = config.getint('DEFAULT', 'maxusers', fallback=20)
  nocase = config.getboolean('DEFAULT', 'case_insensitive', fallback=False)
  count_hidden = config.getboolean('DEFAULT', 'count_hidden', fallback=True)
  idle_barrier = config.getint('DEFAULT', 'idle_barrier', fallback=30)
  threshold = config.getint('DEFAULT', 'speed_threshold', fallback=1024)
  color = config.getint('DEFAULT', 'color', fallback=1)
  debug = config.getint('DEFAULT', 'debug', fallback=0)
  geoip2_enable = config.getboolean('GEOIP', 'geoip2_enable', fallback=False)
  geoip2_accountid = config['GEOIP']['geoip2_accountid']
  geoip2_licensekey = config['GEOIP']['geoip2_licensekey']
  geoip2_proxy = config.get('GEOIP', 'geoip2_proxy', fallback=None)
  layout['header'] = config.get('THEME', 'header', fallback=default['header'])
  layout['footer'] = config.get('THEME', 'footer', fallback=default['footer'])
  layout['separator'] = config.get('THEME', 'separator', fallback=default['separator'])
  tmpl_sub['logo'] = config.get('THEME', 'logo')
  tmpl_str['upload'] = config['THEME']['template_upload']
  tmpl_str['download'] = config['THEME']['template_download']
  tmpl_str['info'] = config['THEME']['template_info']
  tmpl_str['totals'] = config['THEME']['template_totals']
  tmpl_str['users'] = config['THEME']['template_users']
  tmpl_sub['hr_char'] = config.get('THEME', 'hr_char', fallback=':')
  tmpl_sub['delimiter'] = config.get('THEME' ,'delimiter', fallback='|')
  tmpl_sub['ccode'] = config.get('THEME', 'ccode', fallback='0;35')
  emoji = config.getint('THEME', 'emoji', fallback=0)
except KeyError as e:
  print(f'Check config file (error: {e})')
  sys.exit(1)

chidden = 1 if count_hidden == True else 0


# shm, struct
# default ipc_key: 0x0000dead (57005)

IPC_KEY = ipc_key if ipc_key else "0x0000DEAD"
KEY = int(IPC_KEY,16)
#NULL_CHAR = '\0'
NULL_CHAR = b'\x00'
if debug > 3:
  print(f"DEBUG: IPC_KEY={IPC_KEY} KEY={KEY} sysv_ipc.SHM_RDONLY={sysv_ipc.SHM_RDONLY} fmt =", "{:#010x}".format(KEY), id(KEY))

# conv from structonline.h

stformat = ' \
  64s  24s  256s  h  256s  256s  i  i  \
  2i \
  2i \
  2I \
  2I \
  i  \
'
struct_ONLINE = collections.namedtuple(
  'struct_ONLINE',
  'tagline username status ssl_flag host currentdir groupid login_time \
    tstart_tv_sec tstart_tv_usec  \
    txfer_tv_sec txfer_tv_usec    \
    bytes_xfer1 bytes_xfer2       \
    bytes_txfer1 bytes_txfer2     \
    procid'
)


# get data from gl and init geoip

if maxusers == -1:
  for file in { f'{glrootpath}/../glftpd.conf', f'{glrootpath}/glftpd.conf', '/etc/glftpd.conf' }:
    try:
      with open(file, 'r') as f:
        for line in f.readlines():
          if re.search(r'^max_users \d', line):
            maxusers = 0
            for i in line.split()[1:]:
              maxusers += int(i)
            break
    except:
      pass

try:
  for f in seeallflags:
    if f in os.getenv("FLAGS"):
      showall = 1
      break
  if '5' not in os.getenv("FLAGS"):
    gl_nocolor = 1
except:
  pass

try:
  with open(f'{glrootpath}/etc/group', 'r') as f:
    groupfile = f.readlines()
except:
  with open(f'/etc/group', 'r') as f:
    groupfile = f.readlines()

if _WITH_GEOIP and geoip2_enable == True:
  import geoip2.webservice
  geoip2_client = geoip2.webservice.Client(
    geoip2_accountid,
    geoip2_licensekey, host='geolite.info',
    proxy=None if not geoip2_proxy or geoip2_proxy == 'None' else geoip2_proxy
  )


# theme 
########

layout_keys = ['header', 'footer', 'separator']
tmpl_string_keys = ['upload', 'download', 'info', 'totals', 'users']
tmpl_sub_keys = ['delimiter', 'hr_char']

for k in layout_keys:
  try:
    layout[k]
  except Exception as e:
    print(f"Theme setting not found, trying file instead... (error: {e})")
    try:
      file = config.get('DEFAULT', f'{k}file')
      with open(f'{glrootpath}{file}', 'r') as f:
        layout[k] = f.read().strip()
    except Exception as e:
      print(f"File not found for theme '{k}' (error: {e})")

# use unicode for spy and xxl mode and colors/emoji

if _WITH_SPY and spy_mode:
  tmpl_str_spy = {}
  for k in tmpl_string_keys:
    tmpl_str_spy[k] = config.get('SPYMODE', f'template_spy_{k}', fallback=config['THEME'][f'template_{k}']).encode().decode('unicode-escape')
  tmpl_sub['ccode_spy'] = config.get('SPYMODE', 'ccode_spy', fallback='0;30;1')
  tmpl_sub['ccode_spy_sep'] = config.get('SPYMODE', 'ccode_spy_sep', fallback='0;31')
  tmpl_sub['ccode_spy_tot'] = config.get('SPYMODE', 'ccode_spy_tot', fallback='1;37')
  tmpl_sub['ccode'] = tmpl_sub['ccode_spy']
  layout['separator_spy'] = string.Template(config['SPYMODE']['separator_spy']).substitute(tmpl_sub).encode().decode('unicode-escape')

if _WITH_XXL and xxl_mode:
  tmpl_str_xxl = {}
  for k in tmpl_string_keys:
    tmpl_str_xxl[k] = config.get('XXLMODE', f'template_xxl_{k}', fallback=config['THEME'][f'template_{k}'])
  tmpl_sub['delimiter'] = config.get('XXLMODE' ,'delimiter_xxl', fallback='|')

if tmpl_sub['ccode'] or tmpl_sub['ccode_spy'] or emoji:
  for k in layout_keys:
    layout[k] = string.Template(layout[k]).substitute(tmpl_sub).encode().decode('unicode-escape')
  for k in tmpl_string_keys:
    tmpl_str[k] = tmpl_str[k].encode().decode('unicode-escape')
  for k in tmpl_sub_keys:
    tmpl_sub[k] = string.Template(tmpl_sub[k]).substitute(tmpl_sub).encode().decode('unicode-escape')
  
# strip colors from output if running from gl and '5' is not in FLAGS, or color=0, or xxl

if ((tmpl_sub['ccode'] or tmpl_sub['ccode_spy']) and gl_nocolor == 1) or color == 0 or xxl_mode:
  re_esc = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
  for k in layout_keys:
    layout[k] = re_esc.sub('', layout[k])
  for k in tmpl_sub_keys:
    tmpl_sub[k] = re_esc.sub('', tmpl_sub[k])
  if _WITH_SPY and spy_mode:
    layout['separator_spy'] = re_esc.sub('', layout['separator_spy'])


# functions
############

def get_group(gid):
  """
  get group name using gid
  """
  g_name = "NoGroup"
  for line in groupfile:
    if line.split(':')[2] == str(gid):
      g_name = line.split(':')[0]
      return g_name


def get_gid(g_name):
  """
  get gid using group name
  """
  gid = 0
  for line in groupfile:
    if line.split(':')[0] == g_name:
      gid = line.split(':')[2]
      return gid


def filesize(filename):
  """
  get filesize in bytes
  """
  for f in filename, f'{glrootpath}{filename}':
    try:
      return os.path.getsize(f)
    except:
      pass
  return 0


def showusers(mode, ucomp, raw, repeat, user, x, chidden, geoip2_client, downloads, uploads,
             total_up_speed, total_dn_speed, browsers, idlers, onlineusers, geoip2_buf, geoip2_shown_ex):
  """
  output formatted user stats
  """ 
  # NOTE:
  #   to test total up/dn speed set vars:
  #     uploads, downloads, total_up_speed, total_dn_speed = 10, 3, 18576, 8576   # 1048576 (1024*1024)
  #   examples of 'status' output:
  #     b'STOR filename'
  #     b'LIST -al\x00partof-DIR\x003/0504/TEST2\x00/foo-BAR/1'
  #     b'RETR filename.rar\x00X/',
  #     b'STAT'
  #     b'PASV'
  #     b'Connecting...'
  # (OLD) glftpd 2.11: username = user[x].username.decode().split(NULL_CHAR, 1)[0]
  username = user[x].username.split(NULL_CHAR, 1)[0].decode()
  tagline = user[x].tagline.split(NULL_CHAR, 1)[0].decode()
  currentdir = user[x].currentdir.split(NULL_CHAR, 1)[0].decode()
  u_status = user[x].status.split(NULL_CHAR, 1)[0].decode()
  tstop_tv_sec = calendar.timegm(time.gmtime())
  tstop_tv_usec = datetime.datetime.now().microsecond
  host = g_name = traf_dir = None
  speed = pct = mask = noshow = 0
  maskchar = ' '
  bar = ""
  userip = '0.0.0.0'
  iso_code = "xX"

  # skip if host is empty
  if user[x].host != b'':
    host = user[x].host.split(NULL_CHAR, 1)[0].decode()
    (_, addr) = host.split('@', 2)[0:2]
    # ipv4/6
    # if re.search(r'([\d.]{7,}|:)', addr):
    if (''.join((addr).split('.', 3)).isdigit()) or (':' in addr):
      userip = addr
    # not fqdn
    elif not '.' in addr:
      userip = '127.0.0.1' if addr == 'localhost' else '0.0.0.0'
    else:
      try:
        userip = socket.gethostbyname(addr)
      except:
        pass

  if len(u_status) > 5 and not u_status[5:].startswith('-'):
    filename = u_status[5:]
  else:
    filename = ''

  if user[x].groupid >= 0:
    g_name = get_group(user[x].groupid)

  # check if user in hidden users/groups
  if ((nocase and ((username.lower() in husers.lower()) or (g_name.lower() in hgroups.lower()))) or
      ((username in husers) or (g_name in hgroups))):
    if showall:
      maskchar = '*'
    else:
      noshow += 1

  if noshow == 0 and mpaths:
    if ((maskchar == '') and (currentdir in mpaths.split(' ') or (f'{currentdir}/' in mpaths.split(' ')))):
      if showall:
        maskchar = '*'
      else:
        mask += 1

  if _WITH_GEOIP and geoip2_enable == True:
    if debug == 0:
      if geoip2_buf.get(userip):
        iso_code = geoip2_buf[userip]
      else:
        try:
          iso_code = geoip2_client.country(userip).country.iso_code
          geoip2_buf[userip] = iso_code
        except Exception as e:
          if (e.__class__.__name__ == 'AddressNotFoundError' or e.__class__.__name__ == 'reqOutOfQueriesError') and geoip2_shown_ex == 0:
            geoip2_shown_ex = 1
            print()
            print ("{message:<80}".format(message=f'Error: geoip2 {e.__class__.__name__} ({e})'))
            print()
            time.sleep(2.5)
            print(f'\N{ESC}[3F')
            print(f'\N{ESC}[0J')
            print(f'\N{ESC}[3F')
          else:
            pass
    else:
      # when debugging dont pass exception, skip rfc1918 ip's
      j = 0
      for i in [ '127.', '10.', '172.16.1', '172.16.2', '172.16.3', '192.168.' ]:
        if userip.startswith(i):
          j += 1
          if debug > 3:
            print(f'DEBUG: geoip2 MATCH = {i} in {userip}')
          break
      if j == 0:
        if geoip2_buf.get(userip):
          print(f'DEBUG: cache geoip2_buf[userip]={geoip2_buf[userip]}')
          iso_code = geoip2_buf[userip]
        else:
          try:
            iso_code = geoip2_client.country(userip).country.iso_code
            geoip2_buf[userip] = iso_code
          except Exception as e:
            print ("{message:<80}".format(message=f'Error: geoip2 {e.__class__.__name__} {e}'))

    userip = f'{userip} {iso_code}' if (userip and iso_code) else userip
  
  # NOTE: when testing bytes_xfer1, use replace since namedtuple is immutable:
  #       user[x] = user[x]._replace(bytes_xfer1=150000)  

  # ul speed
  if (user[x].status[:5] == b'STOR ' or user[x].status[:5] == b'APPE ') and user[x].bytes_xfer1:
    mb_xfered = abs(user[x].bytes_xfer1 / 1024 / 1024)
    traf_dir = "Up"
    speed = abs(user[x].bytes_xfer1 / 1024 / ((tstop_tv_sec - user[x].tstart_tv_sec) + (tstop_tv_usec - user[x].tstart_tv_usec) / 1000000))
    if ((not noshow and not mask and maskchar != '*') or chidden):
      total_up_speed += speed
      uploads += 1
    if not mask:
      pct = -1
      bar = '?->'
  # dn speed
  elif user[x].status[:5] == b'RETR ' and user[x].bytes_xfer1:
    mb_xfered = 0
    traf_dir = "Dn"
    realfile = currentdir
    my_filesize = filesize(realfile)
    if my_filesize < user[x].bytes_xfer1:
      my_filesize = user[x].bytes_xfer1
    pct = abs(user[x].bytes_xfer1 / my_filesize * 100)
    i = 15 * user[x].bytes_xfer1 / my_filesize
    i = 15 if 1 > 15 else i
    #for x in range(0, int(i)):
    #  bar += 'x' 
    bar = '{:x{align}{width}}'.format('', width=int(abs(i)), align='<')
    speed = abs(user[x].bytes_xfer1 / 1024 / ((tstop_tv_sec - user[x].tstart_tv_sec) + (tstop_tv_usec - user[x].tstart_tv_usec) / 1000000))
    if ((not noshow and not mask and maskchar != '*') or chidden):
      total_dn_speed += speed
      downloads += 1
  # idle time
  else:
    bar = filename = ""
    pct = mb_xfered = 0
    seconds = tstop_tv_sec - user[x].tstart_tv_sec
    if ((not noshow and not mask and maskchar != '*') and chidden):
      if seconds > idle_barrier:
        idlers += 1
      else:
        browsers += 1
    if not raw:
      status = 'Idle: {:>9.9}'.format(time.strftime("%H:%M:%S", time.gmtime(seconds)))
    elif raw == 1:
      status = '"ID" {}'.format(time.strftime("%S", time.gmtime(seconds)))
    else:
      status = 'idle|{}'.format(time.strftime("%H|%M|%S", time.gmtime(seconds)))

  online = '{}'.format(time.strftime("%H:%M:%S", time.gmtime(tstop_tv_sec - user[x].login_time)))

  # format both Up/Dn speed to KB/s MB/s GB/s
  if speed and (traf_dir == "Up" or traf_dir == "Dn"):
    if not mask and not raw:
      if (len(filename) > 15):
        # filename = '{:<.{prec}}'.format(filename, prec=int(m))
        filename = '{:<.15}'.format(filename, align='<')
      if (speed > (threshold * threshold)):
        status = '{}: {:7.2f}GB/s'.format(traf_dir, (speed / 1024 / 1024))
      elif (speed > threshold):
        status = '{}: {:7.1f}MB/s'.format(traf_dir, (speed / 1024))
      else:
        status = '{}: {:7.0f}KB/s'.format(traf_dir, speed)
    elif raw == 1:
      status = '"{}" {:.0f}'.format(traf_dir.upper(), speed)
    else:
      status = '{}ld| {:.0f}'.format(traf_dir.lower(), speed)

  if debug > 0:
    print(f'DEBUG: showusers mode={mode} ucomp={ucomp} raw={raw} repeat={repeat} username={username} x={x} hidden={chidden} showall={showall} noshow={noshow} mask={mask} maskchar={maskchar}')

  # show stats of users
  if mode == 0 and raw != 3:
    if (raw == 0 and (showall or (not noshow and not mask and maskchar != '*'))):
      if (mb_xfered):
        print(string.Template(tmpl_str['upload']).substitute(tmpl_sub).format(username=username, g_name=g_name, status=status, mb_xfered=mb_xfered))
      else:
        print(string.Template(tmpl_str['download']).substitute(tmpl_sub).format(username=username, g_name=g_name, status=status, pct=pct, bar=bar))
      print(string.Template(tmpl_str['info']).substitute(tmpl_sub).format(
        tagline=tagline, userip=userip if userip != '0.0.0.0' else addr,  online=online, filename=filename)
      )
      print(layout['separator'])
    elif (raw == 1 and (showall or (not noshow and not mask and maskchar != '*'))):
      print('"USER" "{username}" "{g_name}" "{status}" "{tagline}" "{online}" "{filename}" "{mb_xfered}" "{currentdir}" "{procid}" "{host}" "{iso_code}" "{userip}"'.format(
          username=username, g_name=g_name, status=status, tagline=tagline, online=online, filename=filename, 
          mb_xfered=mb_xfered, currentdir=currentdir, procid=user[x].procid, host=host, iso_code=iso_code, userip=userip
        )
      )
    elif (showall or (not noshow and not mask and maskchar != '*')):
      print("{}|{}|{}|{}|{}".format(username, g_name, tagline, status, filename))
    if ((not noshow and not mask and maskchar != '*' or chidden)):
      onlineusers += 1
  elif raw == 3:
    if ((not noshow and not mask and maskchar != '*' or chidden)):
      onlineusers += 1
  # show stats for username, if specified as command-line argument
  elif ((ucomp and username) and (ucomp == username)) and (not xxl_mode):
    if _WITH_ALTWHO:
      if (not raw and (showall or (not noshow and not mask and maskchar != '*'))):
        if mb_xfered:
          print("{} : {:1}{}/{} has xfered {:.1f}MB of {} and has been online for {:8.8}.".format(status, maskchar, username, g_name, mb_xfered, filename, online))
        elif filename:
          print("{} : {:1}{}/{} has xfered {:.0f}% of {} and has been online for {:8.8}.".format(status, maskchar, username, g_name, pct, filename, online))
        else:
          print("{} : {:1}{}/{} has been online for {:8.8s}.".format(status, maskchar, username, g_name, online))
      elif (raw == 1 and (showall or (not noshow and not mask and (maskchar != '*')))):
        print("\"USER\" \"{:1}\" \"{}\" \"{}\" {} \"{}\" \"{}\" \"{}\" \"{:.1f}{}\" \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"".format(
            maskchar, username, g_name, status, tagline, online, filename,
            (pct if pct >= 0 else mb_xfered), ("%" if pct >= 0 else "MB"),
            currentdir, user[x].procid, host, iso_code, userip
          )
        )
      elif (showall or (not noshow and not mask and (maskchar != '*'))):
        print("{}|{}|{}|{}|{}".format(username, g_name, tagline, status, filename))
    else:
      if not onlineusers:
        if (not raw and (showall or (not noshow and not mask and maskchar != '*'))):
          print("\002{}\002 - {}".format(username, status))
        elif (raw == 1 and (showall or (not noshow and not mask and maskchar != '*'))):
          print("\"USER\" \"{}\" {}".format(username, status))
        elif (showall or (not noshow and not mask and maskchar != '*')):
          print("\002{}\002 - {}".format(username, status))
      else:
        if (not raw and (showall or (not noshow and not mask and maskchar != '*'))):
          print(" - {}".format(status))
        elif (raw == 1 and (showall or (not noshow and not mask and maskchar == '*'))):
          print("\"USER\" \"\" {}".format(status))
        elif (showall and (not noshow and not mask and maskchar != '*')):
          print(" - {}".format(status))
    if (not noshow and not mask and maskchar != '*'):
      onlineusers += 1
    elif chidden:
      onlineusers += 1
    filename = ""

  # xxl_mode: wide output, use columns from terminal size as width
  elif _WITH_XXL and xxl_mode:
    upload = download = info = ''
    columns = os.get_terminal_size().columns
    if bar:
      pad = '{:{fill}{align}{width}}'.format('', fill='.', align='<', width=(15-abs(len(bar))))
      bar = '{}{}'.format(bar, pad)
    else:
      bar = '-' 
    filename = filename if filename else '---'
    if (mb_xfered):
        upload = string.Template(tmpl_str_xxl['upload']).substitute(tmpl_sub).format(
          username=username, g_name=g_name, tagline=tagline, status=status, mb_xfered=mb_xfered
        )
        print ("{message:<{col}.{col}}".format(col=columns, message=upload))
    else:
      download = string.Template(tmpl_str_xxl['download']).substitute(tmpl_sub).format(
        username=username, g_name=g_name, tagline=tagline, status=status.replace('  ', ' ').upper(), pct=pct, bar=bar
      )
      print ("{message:<{col}.{col}}".format(col=columns, message=download))
    info = string.Template(tmpl_str_xxl['info']).substitute(tmpl_sub).format(
      userip = userip if userip != '0.0.0.0' else addr, online=online, filename=filename
    )
    print ("{message:<{col}.{col}}".format(col=columns, message=info))
    # separator:        print("{message:<{col}.{col}}".format(col=columns, message=layout['separator']))
    # sep w/ calc len:  msg_len = max(len(upload), len(download), len(info))
    #                   print("{message:<{col}.{col}}".format(col = min((msg_len+1)*2, columns), message=layout['separator'] * msg_len))
    print()
    onlineusers += 1

  # spymode: try to show as much useful info as possible..
  
  elif _WITH_SPY and spy_mode:
    # show pct/bar or currentdir on right side
    if not pct and not bar:
      pct_spy = ''
    else:
      pct_spy = "{:>4.0f}%:".format(pct)
    if bar:
      if bar == '?->':  
        bar_spy = "{:<22.22}".format(user[x].status.split(NULL_CHAR, 1)[0].decode()[5:]) if (len(status) > 5) else "{:<22.22}".format(' ')
      else:
        bar_spy = "{:<16.16s}".format(bar)
    else:
      # show '-' to confirm (big) file is in progress
      if pct > 0:
        bar_spy = "{:<16.16s}".format('-')
      if not pct:
        bar_spy = "{:<22.22}".format(currentdir.replace('/site', ''))
    pb_spy=f'{pct_spy} {bar_spy}'
    if (mb_xfered):
      print(string.Template(tmpl_str_spy['upload']).substitute(tmpl_sub).format(username=username, g_name=g_name, status=status, mb_xfered=mb_xfered))
    else:
      print(string.Template(tmpl_str_spy['download']).substitute(tmpl_sub).format(username=username, g_name=g_name, status=status, pb_spy=pb_spy))
    # right: show filename or status 
    if (u_status[:5] in ['RETR ', 'STOR ']):
      fn_spy = f'file: {filename}'
    elif (u_status[:5] in ['LIST ', 'STAT ', 'SITE ']):      
      fn_spy = u_status
    elif u_status[5:].startswith('-') or (u_status == 'Connecting...'):
      fn_spy = u_status
    else:
      fn_spy = filename
    # left: rotate between ip or tagline on left
    if repeat % 8 in range(0, 5):
      print(string.Template(tmpl_str_spy['info']).substitute(tmpl_sub).format(info="{:8.8s} {:>18.18s}".format(
        tagline, userip if userip != '0.0.0.0' else addr), online=online, fn_spy=fn_spy)
      )
    else:
      print(string.Template(tmpl_str_spy['info']).substitute(tmpl_sub).format(info=tagline, online=online, fn_spy=fn_spy))
    print(string.Template(layout['separator_spy']).substitute(tmpl_sub).format('', x=x))
    onlineusers += 1

  return dict(
    downloads=downloads, uploads=uploads, total_up_speed=total_up_speed, total_dn_speed=total_dn_speed, 
    browsers=browsers, idlers=idlers, onlineusers=onlineusers, geoip2_buf=geoip2_buf, geoip2_shown_ex=geoip2_shown_ex
  )


def showtotals(raw, maxusers, downloads, uploads, total_up_speed, total_dn_speed, browsers, idlers, onlineusers, geoip2_buf, geoip2_shown_ex):
  """
  output formatted totals
  """
  if (total_up_speed > (threshold*threshold)) or (total_dn_speed > (threshold*threshold)):
    total_up_speed = (total_up_speed / 1024 / 1024)
    total_dn_speed = (total_dn_speed / 1024 / 1024)
    speed_unit ='GB/s'
  elif (total_up_speed > threshold) or (total_dn_speed > threshold):
    total_up_speed = (total_up_speed / 1024)
    total_dn_speed = (total_dn_speed / 1024)
    speed_unit ='MB/s'
  else:
    speed_unit = 'KB/s'
  if not raw:
    if _WITH_SPY and spy_mode:
      print(string.Template(tmpl_str_spy['totals']).substitute(tmpl_sub).format(
        uploads=uploads, total_up_speed=total_up_speed,downloads=downloads, total_dn_speed=total_dn_speed,
        total=uploads + downloads, total_speed = total_up_speed + total_dn_speed, unit=speed_unit
      ))
      print(string.Template(tmpl_str_spy['users']).substitute(tmpl_sub).format(space=' ', onlineusers=onlineusers, maxusers=maxusers))
    elif _WITH_XXL and xxl_mode:
      totals = string.Template(tmpl_str_xxl['totals']).substitute(tmpl_sub).format(
        uploads=uploads, total_up_speed=total_up_speed,downloads=downloads, total_dn_speed=total_dn_speed,
        total=uploads + downloads, total_speed = total_up_speed + total_dn_speed, unit=speed_unit
      )
      users = string.Template(tmpl_str_xxl['users']).substitute(tmpl_sub).format(space=' ', onlineusers=onlineusers, maxusers=maxusers)
      print ("{message:<{col}.{col}}".format(col=os.get_terminal_size().columns, message=f'{totals} {users}'))
    else:
      print(string.Template(tmpl_str['totals']).substitute(tmpl_sub).format(
        uploads=uploads, total_up_speed=total_up_speed,downloads=downloads, total_dn_speed=total_dn_speed,
        total=uploads + downloads, total_speed = total_up_speed + total_dn_speed, unit=speed_unit
      ))
      print(string.Template(tmpl_str['users']).substitute(tmpl_sub).format(space=' ', onlineusers=onlineusers, maxusers=maxusers))
  elif raw == 1:
    print('"STATS" "{uploads}" "{total_up_speed:.1f}" "{downloads}" "{total_dn_speed:.1f}" "{total}" "{total_speed:.1f}"'.format(
        uploads=uploads, total_up_speed=total_up_speed,
        downloads=downloads, total_dn_speed=total_dn_speed,
        total=uploads + downloads, total_speed = total_up_speed + total_dn_speed,
      ) 
    )
  elif raw == 3:
    print('{uploads} {total_up_speed:.1f} {downloads} {total_dn_speed:.1f} {total} {total_speed:.1f} {browsers} {idlers} {onlineusers} {maxusers}'.format(
        uploads=uploads, total_up_speed=total_up_speed, downloads=downloads, total_dn_speed=total_dn_speed,
        total=uploads + downloads, total_speed = total_up_speed + total_dn_speed,
        browsers=browsers, idlers=idlers, onlineusers=onlineusers, maxusers=maxusers
      )
    )


def spy_break(signal_received, frame):
  """
  handle ctrl-c break
  """ 
  print()
  print ("{message:<80}".format(message=f"Exiting py-who spy mode..."))
  print()
  if _WITH_GEOIP and geoip2_enable:
    geoip2_client.close()
  sys.exit(0)


def spy_user_wait(mode, msg):
  """
  mode 0: show progress meter, e.g. [ xxxxxxx... ]
  mode 1: wait for user to press ENTER
  """
  fill = 'x' if mode == 0 else '.'
  i = 0
  while True:
    input = select.select([sys.stdin], [], [], 0.5)[0]
    if input:
      print(f'\N{ESC}[0J')
      break
    if mode == 0:
      pad = '.' * (10-i)
      if i > 10:
        break
    elif mode == 1:
      pad = ' ' * (3-i)
      if i > 3:
        i = 0
    progress = '{:{fill}{align}{width}}'.format('', fill=fill, align='<', width=int(i))
    output = '{} [ {}{} ]' if mode == 0 else '{}{}{}'
    print(output.format(msg, progress, pad, end=""))
    print(f'\N{ESC}[2F')
    i += 1


def spy_usage():
  """ 
  show usage text and prompt for user input
  """
  if x == 1:
    u_range = '0'
  elif x > 1:
    u_range = f'0-{x-1}'
  else:
     u_range = '<num>'
  #print()
  print(f"> To view user info press '{u_range}' or to kick use 'k <num>' (needs root)")
  print(f"> To quit press 'q' or 'CTRL-C' ... Type [{u_range},k,q] <ENTER> :")
  print(f" ___", end="")
  print(f'\N{ESC}[2A')
  print(f'\N{ESC}[1C')


def spy_input_action(user, user_action, screen_redraw):
  """
  get user input and run action after ENTER
  """
  user_pid = 0
  orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
  fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)
  s_line = sys.stdin.read(5)
  # quit
  if 'q' == s_line.rstrip():
    print ("{:<80}".format(' '))
    print ("{message:<80}".format(message=f"Exiting py-who spy mode...", end=""))
    print()
    sys.exit(0)
  # userinfo
  if s_line[:2].strip().isdigit() and int(s_line[:2].strip()) in range(0, x):
    user_action = 1
    u_name = user[int(s_line.strip())].username.split(NULL_CHAR, 1)[0].decode()
    try:
      with open(f'{glrootpath}/ftp-data/users/{u_name}', 'r') as f:
        userfile = f.readlines()
    except:
      try:
        with open(f'/ftp-data/users/{u_name}', 'r') as f:
          userfile = f.readlines()
      except:
        pass
    try:
      userfile
    except:
      print ("{message:<80}".format(message=f" User '{u_name}' not found..."))
      time.sleep(2)
    else:
      print(f'\N{ESC}[2J')
      print(f'\N{ESC}[H')
      print(string.Template(layout['header']).substitute(tmpl_sub))
      i=0
      while i < len(user):
        if user[i].username == user[int(s_line)].username:
          tls_msg = tls_mode[user[i].ssl_flag] if user[i].ssl_flag in range(0, len(tls_mode)) else 'UNKNOWN'
          print(f"  LOGIN [#{i}] from '{user[i].username.split(NULL_CHAR, 1)[0].decode()}' (PID: {user[i].procid}):")
          print(f'    RHost: {user[i].host.split(NULL_CHAR, 1)[0].decode()} SSL: {tls_msg}')
          print(f'    Tagline: {user[i].tagline.split(NULL_CHAR, 1)[0].decode()}')
          print(f'    Currentdir: {user[i].currentdir.split(NULL_CHAR, 1)[0].decode()}')
          print(f'    Status: {user[i].status.split(NULL_CHAR, 1)[0].decode()}')
        i += 1
      print(string.Template(layout['separator']).substitute(tmpl_sub))
      print(f'  USERFILE:')
      for line in userfile:
        j = 0
        for field in [ 'FLAGS', 'CREDITS', 'IP' ]:
          if field in line:
            if line.startswith('CREDITS'):
              print("{:>4.4}{}".format(' ', re.sub(r'^(CREDITS [^0]\d+).*', r'\1 MB', line)), end="")
            else:
              print("{:>4.4}{}".format(' ', line.strip()))
            j += 1
      print(string.Template(layout['footer']).substitute(tmpl_sub))
      spy_user_wait(1, "  > Press ENTER to continue ")
      screen_redraw = 1
  # kill user
  elif (s_line.rstrip().startswith('k')):
    user_action = 2
    screen_redraw = 1
    s_line = re.split(r'k\s?', s_line.rstrip())[1]
    if s_line.isdigit() and int(s_line) in range(0, x):
      user_pid = user[int(s_line)].procid
      if os.popen(f'ps --no-headers -o comm -p {user_pid}').read().strip() == 'glftpd':
        print ("{message:<80}".format(message=' '))
        try:
          os.kill(int(user_pid), 15)
          print ("{message:<80}".format(message=f"Killed PID '{user_pid}' ..."))
          time.sleep(2)
        except Exception as e:
          print ("{message:<80}".format(message=f'Error: kill user {e}'))
          time.sleep(3)
        print ("{message:<80}".format(message=' '))
    print(f'\N{ESC}[2J')
    print(f'\N{ESC}[H')
  # handle any other key presses
  elif user_action == 0 and len(s_line) > 0:
    user_action = 3
    screen_redraw = 1
    print ("{message:<80}".format(message=' '))
    print ("{:>4.4}{message:<76}".format(' ', message=f"User not found or invalid option ..."))
    print ("{message:<80}".format(message=' '))
    time.sleep(1)
  else:
    user_action = 0
  s_line = ''
  return [ user_action, screen_redraw ]


# main: read shm, call showusers() and showtotals()
####################################################

# get username from cli arg
user_arg = None
if user_idx != 0:
  try:
    user_arg = sys.argv[user_idx]
  except:
    pass

# init screen drawing related vars
repeat = 0
user_action = 0         # 1=userinfo 2=kill user 3=other
screen_redraw = 0       # 1=redraw logo/header

# clear screen
if _WITH_SPY and spy_mode:
  print(f'\N{ESC}[2J')
  print(f'\N{ESC}[H')

# show logo with header
if len(sys.argv) == 1 and not raw_output or (_WITH_SPY and spy_mode):
  print(string.Template(layout['header']).substitute(tmpl_sub))
  pass
elif _WITH_XXL and xxl_mode:
  print()
  print('[ PY-WHO ]\n'.format())

# loop: if in spymode keep repeating indefinitely, for non-spy modes quit after single iteration

while (_WITH_SPY and spy_mode) or (not spy_mode and repeat < 1):
  if debug == 0:
    try:
      memory = sysv_ipc.SharedMemory(KEY, flags = sysv_ipc.SHM_RDONLY, mode = 0)
    except sysv_ipc.ExistentialError as e:
      if not raw_output:
        print("Error: {} (0x{:08X})\n{:7.7}No users are logged in?\n".format(e, KEY, ' '))
      else:
        print("\"ERROR\" \"No users logged in?\" \"{}\" \"0x{:08X}\"".format(e, KEY))
      sys.exit(1)
  else:
    memory = sysv_ipc.SharedMemory(KEY, flags = sysv_ipc.SHM_RDONLY, mode = 0)
  buf = memory.read()
  
  # spymode: on redraw first clear screen, then show logo/header,
  #          move cursor up using ascii escape codes, then show user[x] lines
  if repeat > 0 and user_action == 0:
    # debug: print vars, sleep 1s to view them
    if (debug > 4):
      print('DEBUG: spy vars =', screen_redraw, user_action)
      time.sleep(1)
    if screen_redraw == 0:
      # go back up and clear 'l' lines per user + totals + help lines
      l = (len(user) * 3 + 3 + 4)
      print(f'\N{ESC}[{l}F')
      print(f'\N{ESC}[0J')
      print(f'\N{ESC}[2F')
    else:
      print(f'\N{ESC}[2J')
      print(f'\N{ESC}[H')
      print(string.Template(layout['header']).substitute(tmpl_sub))
      screen_redraw = 0

  # reset user data for every repeat
  user = []
  x = 0
  kwargs = dict(
    downloads=downloads, uploads=uploads, total_up_speed=total_up_speed, total_dn_speed=total_dn_speed,
    browsers=browsers, idlers=idlers, onlineusers=onlineusers, geoip2_buf=geoip2_buf, geoip2_shown_ex=geoip2_shown_ex
  )
  # user loop: unpack shm (buf) as py struct, loop over struct.iter (904 bytes)
  #            make tuples in a list (user), skip if empty
  for user_tuple in struct.iter_unpack(stformat, buf):
    if struct_ONLINE._make(user_tuple).procid:
      user.insert(x, struct_ONLINE._make(user_tuple))
      if user_action == 0:
        # totusers = maxusers if totusers > maxusers else totusers
        # totusers = len(user)
        if (debug > 2):
          print(f'DEBUG: user loop sys.argv={sys.argv} (len={len(sys.argv)}) user_idx={user_idx} user_arg={user_arg} raw_output={raw_output} repeat={repeat} x={x} chidden={chidden}')
        if raw_output < 2:
          kwargs = showusers(len(sys.argv) - raw_output - 1, user_arg, raw_output, repeat, user, x, chidden, geoip2_client, **kwargs)
        elif len(sys.argv) == 1:
          kwargs = showusers(len(sys.argv) - 1, user_arg, raw_output, repeat, user, x, chidden, geoip2_client, **kwargs)
        elif raw_output == 3:
          kwargs = showusers(len(sys.argv) - 2, user_arg, raw_output, repeat, user, x, chidden, geoip2_client, **kwargs)
        else:
          kwargs = showusers(0, user_arg, raw_output, repeat, user, x, chidden, geoip2_client, **kwargs)
      x += 1
  if _WITH_SPY and spy_mode:
    geoip2_shown_ex = kwargs['geoip2_shown_ex']

  # show totals or single user stats
  if user_action == 0:
    if len(sys.argv) == 1 or raw_output == 3 or (_WITH_SPY and spy_mode) or (_WITH_XXL and xxl_mode):
      showtotals(raw_output, maxusers, **kwargs)
      if not raw_output and not xxl_mode:
        print(string.Template(layout['footer']).substitute(tmpl_sub))
    elif user_arg and not xxl_mode:
      u_found = False
      i = 0
      while i < len(user):
        if user[i].username.split(NULL_CHAR, 1)[0].decode() == user_arg:
          u_found = True
          break
        i += 1
      if not u_found:
        if not raw_output:
          print(f"\002{user_arg}\002 is not online\n")
        else:
          print(f"\"ERROR\" \"User {user_arg} not online.\"\n")
        sys.exit(1)
    if (_WITH_ALTWHO and not raw_output) or (_WITH_XXL and xxl_mode):
      print()

  # spy-mode: handle keyboard input
  if _WITH_SPY and spy_mode:
    signal.signal(signal.SIGINT, spy_break)
    if user_action == 0:
      spy_usage()
    result = spy_input_action(user, user_action, screen_redraw)
    [ user_action, screen_redraw ] = result
    if user_action == 0:
      time.sleep(1)
    if _WITH_GEOIP and geoip2_enable:
      time.sleep(2)

  repeat += 1

try:
  memory.detach()
except:
  pass
if _WITH_GEOIP and geoip2_enable:
  geoip2_client.close()
sys.exit(0)

# fuquallkthnxbye.
