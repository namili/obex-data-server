#!/usr/bin/python

import dbus
import dbus.decorators
import dbus.glib
import gobject
from os.path import basename,splitext
from signal import *
from time import ctime

bt_address = '00:12:EE:7C:30:D4'
#bt_address = '00:01:E3:54:D0:87'
folder_to_go_to = 'Pictures'
folder_to_create = 'Nonsense'
file_to_send = '/home/skirsdeda/Desktop/x.jpg'

class Tester:
    total_bytes = -1
    exec_iter = 0
    
    def __init__(self):
        self.bus = dbus.SessionBus()
        
        manager_obj = self.bus.get_object('org.openobex', '/org/openobex')
        self.manager = dbus.Interface(manager_obj, 'org.openobex.Manager')
        
        self.session_path = self.manager.CreateBluetoothSession(bt_address, '00:00:00:00:00:00', 'ftp')
        print 'Session object: ', self.session_path
        session_obj = self.bus.get_object('org.openobex', self.session_path)
        self.session = dbus.Interface(session_obj, 'org.openobex.Session')

        self.manager.connect_to_signal('SessionConnected', self.connected_cb)
        self.session.connect_to_signal('Disconnected', self.disconnected_cb)
        self.session.connect_to_signal('Closed', self.closed_cb)
        self.session.connect_to_signal('Cancelled', self.cancelled_cb)
        self.session.connect_to_signal('TransferStarted', self.transfer_started_cb)
        self.session.connect_to_signal('TransferProgress', self.transfer_progress_cb)
        self.session.connect_to_signal('TransferCompleted', self.transfer_completed_cb)
        self.session.connect_to_signal('ErrorOccurred', self.error_occurred_cb)
        
        self.main_loop = gobject.MainLoop()
        self.main_loop.run()
    
    def connected_cb(self, session_path):
        if session_path == self.session_path:
            print 'Connected'
            self.run()
        
    def disconnected_cb(self):
        print 'Disconnected'
        self.call_method('Close')
        
    def closed_cb(self):
        print 'Closed'
        self.main_loop.quit()
        
    def cancelled_cb(self):
        print 'Transfer cancelled'
        self.run()

    def transfer_started_cb(self, filename, local_path, total_bytes):
        if self.exec_iter == 3:
            self.call_method('Cancel')
            return
        
        print 'Transfer started (%s, %s, %d)' % (filename, local_path, total_bytes)
        self.total_bytes = total_bytes
        transfer_info = self.call_method('GetTransferInfo')
        print '-- Size           = %s' % transfer_info['Size']
        print '-- RemoteFilename = %s' % transfer_info['RemoteFilename']
        print '-- LocalPath      = %s' % transfer_info['LocalPath']
        if 'Time' in transfer_info:
            print '-- Time           = ', transfer_info['Time']
    
    def transfer_progress_cb(self, bytes_transferred):
        if self.total_bytes != 0:
            print 'Progress: %d %%' % int(float(bytes_transferred)/self.total_bytes*100)
        else:
            print 'Progress'
        
    def transfer_completed_cb(self):
        print 'Transfer completed'
        self.run()
        
    def error_occurred_cb(self, error_name, error_message):
        print 'Error occurred: %s: %s' % (error_name, error_message)
        if error_name == 'org.openobex.Error.LinkError':
            self.call_method('Close')
        self.run()
        
    def call_method(self, method_name, *args):
        to_print = '>>> ' + method_name + '('
        for arg in args:
            to_print += arg + ', '
        print to_print.rstrip(', ') + ')'
        
        try:
            ret = self.session.get_dbus_method(method_name)(*args)
        except dbus.DBusException, e:
            print 'Failed: %s' % e
            return False
            
        return ret
        
    def run(self):
        if self.exec_iter == 0:
            print self.call_method('RetrieveFolderListing')
            print self.call_method('GetCurrentPath')
            
            self.call_method('ChangeCurrentFolder', folder_to_go_to)
            print self.call_method('RetrieveFolderListing')
            
            self.call_method('CreateFolder', folder_to_create)
            print self.call_method('GetCurrentPath')
            
            self.call_method('ChangeCurrentFolderBackward')
            print self.call_method('GetCurrentPath')
            
            self.call_method('DeleteRemoteFile', folder_to_create)
            
            self.call_method('SendFile', file_to_send)
            
            print self.call_method('IsBusy')

        elif self.exec_iter == 1:
            print self.call_method('IsBusy')
            
            path, ext = splitext(file_to_send)
            file_to_save_to = path + '_1' + ext
            self.call_method('CopyRemoteFile', basename(file_to_send), file_to_save_to)
            
        elif self.exec_iter == 2:
            self.call_method('DeleteRemoteFile', basename(file_to_send))
            
            self.call_method('SendFile', file_to_send)
        elif self.exec_iter == 3:
            self.call_method('ChangeCurrentFolderToRoot')
            print self.call_method('GetCurrentPath')
            
            print self.call_method('GetCapability')
            
            self.call_method('Disconnect')
            
        self.exec_iter += 1


if __name__ == '__main__':
    gobject.threads_init()
    dbus.glib.init_threads()

    tester = Tester()
    
