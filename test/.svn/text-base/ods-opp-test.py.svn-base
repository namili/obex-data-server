#!/usr/bin/python

import dbus
import dbus.decorators
import dbus.glib
import gobject
from optparse import OptionParser
import sys

class Tester:
    total_bytes = -1
    progress_started = False
    file_iter = 0
    rotate = '\\|/-'
    rotate_iter = 0
    
    def __init__(self, options, args):
        self.options = options
        self.args = args
        if options.system_bus:
            self.bus = dbus.SystemBus()
        else:
            self.bus = dbus.SessionBus()
        
        manager_obj = self.bus.get_object('org.openobex', '/org/openobex')
        self.manager = dbus.Interface(manager_obj, 'org.openobex.Manager')
        
        self.manager.connect_to_signal('SessionConnected', self.session_connected_cb)
        self.manager.connect_to_signal('SessionConnectError', self.session_connect_error_cb)
        if options.tty_dev:
            self.session_path = self.manager.CreateTtySession(options.tty_dev, 'opp')
        else:
            self.session_path = self.manager.CreateBluetoothSession(
                                        args[0], options.local_device, 'opp')
        session_obj = self.bus.get_object('org.openobex', self.session_path)
        self.session = dbus.Interface(session_obj, 'org.openobex.Session')

        self.session.connect_to_signal('Disconnected', self.disconnected_cb)
        self.session.connect_to_signal('Closed', self.closed_cb)
        self.session.connect_to_signal('Cancelled', self.cancelled_cb)
        self.session.connect_to_signal('TransferStarted', self.transfer_started_cb)
        self.session.connect_to_signal('TransferProgress', self.transfer_progress_cb)
        self.session.connect_to_signal('TransferCompleted', self.transfer_completed_cb)
        self.session.connect_to_signal('ErrorOccurred', self.error_occurred_cb)
        
        self.main_loop = gobject.MainLoop()
        self.main_loop.run()
    
    def session_connected_cb(self, session_path):
        if session_path == self.session_path:
            self.send_file()
        
    def session_connect_error_cb(self, session_path, error_name, error_message):
        if session_path == self.session_path:
            print 'Connection error occurred: %s: %s' % (error_name, error_message)
            self.main_loop.quit()
        
    def disconnected_cb(self):
        self.call_method('Close')
        
    def closed_cb(self):
        self.main_loop.quit()
        
    def cancelled_cb(self):
        if self.progress_started: print
        print 'Transfer cancelled'
        self.send_file()

    def transfer_started_cb(self, filename, local_path, total_bytes):
        self.total_bytes = total_bytes
        self.progress_started = False
        transfer_info = self.call_method('GetTransferInfo')
        for name,value in transfer_info.iteritems():
            print '--', name, '=', value
    
    def transfer_progress_cb(self, bytes_transferred):
        if not self.progress_started:
            print 'Progress:     ',
            self.progress_started = True
        if self.total_bytes != -1:
            sys.stdout.write('\b\b\b\b%3d%%' % int(float(bytes_transferred)/self.total_bytes*100))
            sys.stdout.flush()
        else:
            sys.stdout.write('\b\b\b\b'+self.rotate[self.rotate_iter]+'   ')
            sys.stdout.flush()
            self.rotate_iter += 1
            if self.rotate_iter == 4:
                self.rotate_iter = 0
        
    def transfer_completed_cb(self):
        if self.progress_started: print
        print 'Transfer completed'
        self.send_file()
        
    def error_occurred_cb(self, error_name, error_message):
        if self.progress_started: print
        print 'Error occurred: %s: %s' % (error_name, error_message)
        if error_name != 'org.openobex.Error.LinkError':
            self.send_file()
        
    def call_method(self, method_name, *args):
        try:
            ret = self.session.get_dbus_method(method_name)(*args)
        except dbus.DBusException, e:
            print 'Failed: %s' % e
            return False
            
        return ret
        
    def send_file(self):
        if self.file_iter == len(self.options.files):
            #no more files to send
            self.call_method('Disconnect')
            return
        
        file_to_send = self.options.files[self.file_iter]
        self.file_iter += 1
        print 'Sending:', file_to_send
        self.call_method('SendFile', file_to_send)

if __name__ == '__main__':
    usage = 'Usage: '+sys.argv[0]+' [options] [bt_device] [files]...'
    parser = OptionParser(usage)
    parser.add_option('-l', '--local', dest='local_device',
                      default='00:00:00:00:00:00',
                      help='ADDRESS of Bluetooth adapter to connect from. Default is 00:00:00:00:00:00',
                      metavar='ADDRESS')
    parser.add_option('-y', '--tty', dest='tty_dev',
                      help='Connect to specified TTY device instead of Bluetooth. If TTY device is used, all Bluetooth options are ignored.',
                      metavar='TTY_DEV')
    parser.add_option('-s', '--system-bus', dest='system_bus',
                      action='store_true', default=False,
                      help='Search for obex-data-server on System bus instead of Session bus (use when ods is running in D-Bus System bus)')
    options, args = parser.parse_args()
    
    err1 = ''
    err2 = ''
    if not options.tty_dev and len(args) < 1:
        err1 = 'error: Remote device address not specified'
    if options.tty_dev:
        min_args = 1
    else:
        min_args = 2 
    if len(args) < min_args:
        err2 = 'error: No files to send'
    if err1 or err2:
        print usage
        print
        if err1: print err1
        if err2: print err2
        exit()
    options.files = args[min_args-1:]
    
    tester = Tester(options, args)
