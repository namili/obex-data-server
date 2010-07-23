#!/usr/bin/python

import dbus
import dbus.decorators
import dbus.glib
import gobject
import math
from optparse import OptionParser
import readline
from signal import *
import sys
from xml.dom.minidom import parseString

class Tester:
    total_bytes = -1
    progress_started = False
    preferred_width = 0
    preferred_height = 0
    preferred_encoding = ''
    preferred_transformation = 'stretch'
    image_iter = -1
    image_handles = []
    thumbnail_requested = False
    rotate = '\\|/-'
    rotate_iter = 0
    
    def __init__(self, options, args):
        self.options = options
        self.args = args
        self.bus = dbus.SessionBus()
        
        manager_obj = self.bus.get_object('org.openobex', '/org/openobex')
        self.manager = dbus.Interface(manager_obj, 'org.openobex.Manager')
        
        self.manager.connect_to_signal('SessionConnected', self.session_connected_cb)
        self.manager.connect_to_signal('SessionConnectError', self.session_connect_error_cb)
        if options.remote_display:
            feature = 'remotedisplay'
        else:
            feature = 'imagepush'
        if options.transformation:
            self.preferred_transformation = options.transformation
        self.session_path = self.manager.CreateBluetoothImagingSession(
                                  args[0], options.local_device, feature)
        session_obj = self.bus.get_object('org.openobex', self.session_path)
        self.session = dbus.Interface(session_obj, 'org.openobex.Session')

        self.session.connect_to_signal('Disconnected', self.disconnected_cb)
        self.session.connect_to_signal('Closed', self.closed_cb)
        self.session.connect_to_signal('Cancelled', self.cancelled_cb)
        self.session.connect_to_signal('TransferStarted', self.transfer_started_cb)
        self.session.connect_to_signal('TransferProgress', self.transfer_progress_cb)
        self.session.connect_to_signal('TransferCompleted', self.transfer_completed_cb)
        self.session.connect_to_signal('ErrorOccurred', self.error_occurred_cb)
        self.session.connect_to_signal('ImageHandleReceived', self.image_handle_received_cb)
        
        self.main_loop = gobject.MainLoop()
        self.main_loop.run()
    
    def session_connected_cb(self, session_path):
    	if session_path == self.session_path:
    	    if self.options.size:
    	        width_str, height_str = self.options.size.split('*')
    	        self.preferred_width = int(width_str)
    	        self.preferred_height = int(height_str)
    	    elif self.options.preferred or self.options.capabilities:
    		    caps = self.call_method('GetImagingCapabilities')
    		    if self.options.capabilities:
    		        print caps
    		        self.call_method('Disconnect')
    		    else:
    		        #parse capabilities
    		        pixel = ''
    		        try:
    		            dom = parseString(caps)
    		            format = dom.getElementsByTagName('preferred-format')[0]
    		            self.preferred_encoding = format.getAttribute('encoding')
    		            pixel = format.getAttribute('pixel')
    		            transformation = format.getAttribute('transformation')
    		        except:
    		            #ignore parsing errors because all the elements we parse are optional
    		            pass
    		        if pixel:
    		            range = pixel.split('-')
    		            width_height = '0*0'
    		            if len(range) == 2:
    		                #will be using the upper limit of pixel range
    		                width_height = range[1]
    		            elif len(range) == 1:
    		                width_height = range[0]
    		            width_str, height_str = width_height.split('*')
    		            self.preferred_width = int(width_str)
    		            self.preferred_height = int(height_str)
    		        if transformation:
    		            self.preferred_transformation = transformation
    		
            if not self.options.capabilities:
                self.send_image()
    	
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
        self.send_image()

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
        print 'Transfer completed (Image handle is \''+self.image_handles[-1]+'\')'
        if self.thumbnail_requested:
            print 'Sending thumbnail'
            self.thumbnail_requested = False
        else:
            self.send_image()
        
    def error_occurred_cb(self, error_name, error_message):
        if self.progress_started: print
        print 'Error occurred: %s: %s' % (error_name, error_message)
        if error_name != 'org.openobex.Error.LinkError':
            self.send_image()
        
    def image_handle_received_cb(self, image_handle, thumbnail_requested):
    	self.image_handles.append(image_handle)
    	if thumbnail_requested:
    	    self.thumbnail_requested = True
        
    def call_method(self, method_name, *args):
        try:
            ret = self.session.get_dbus_method(method_name)(*args)
        except dbus.DBusException, e:
            print 'Failed: %s' % e
            return False
            
        return ret
        
    def send_image(self):
        if self.image_iter == len(self.args)-2:
            #no more images to send
            if self.options.remote_display:
                self.remote_display_shell()
            else:
                self.call_method('Disconnect')
            return
        
        self.image_iter += 1
        file_to_send = self.args[self.image_iter+1]
        print 'Sending:', file_to_send
        
        if self.preferred_width != 0:
            width, height, encoding = self.call_method('GetImageInfo', file_to_send)
            new_width = self.preferred_width
            new_height = self.preferred_height
            do_resize = False
            if self.preferred_transformation == 'stretch' and (width > new_width or height > new_height):
                preferred_ratio = float(self.preferred_width)/self.preferred_height
                ratio = float(width)/height
                if ratio > preferred_ratio:
                    new_height = int(math.ceil(height*(float(new_width)/width)))
                    do_resize = True
                else:
                    new_width = int(math.ceil(width*(float(new_height)/height)))
                    do_resize = True
            elif self.preferred_transformation != 'stretch' and (width != new_width or height != new_height):
                do_resize = True
            
            if do_resize: 
                print 'Resized to: %d*%d' % (new_width, new_height)
                self.call_method('PutImageResized', file_to_send,
                                 new_width, new_height,
                                 self.preferred_encoding,
                                 self.preferred_transformation)
            else:
                #no need to resize image
                self.call_method('PutImage', file_to_send)
        else:
            self.call_method('PutImage', file_to_send)
    
    def remote_display_shell(self):
        print 'RemoteDisplay interactive shell. Available commands:'
        print 's image_handle : select image with specified ImageHandle'
        print 'c : display currently selected image'
        print 'n : display next image'
        print 'p : display previous image'
        print 'q : quit'
        while True:
           command = raw_input('>>> ')
           if command.startswith('s '):
               image_handle = command[1:].strip()
               try:
                   i = self.image_handles.index(image_handle)
               except:
                   print 'error: image with such ImageHandle has not been sent'
                   continue
               self.call_method('RemoteDisplaySelectImage', image_handle)
           elif command.strip() == 'c':
               self.call_method('RemoteDisplayShowCurrentImage')
           elif command.strip() == 'n':
               self.call_method('RemoteDisplayShowNextImage')
           elif command.strip() == 'p':
               self.call_method('RemoteDisplayShowPreviousImage')
           elif command.strip() == 'q':
               self.call_method('Disconnect')
               break
           else:
               print 'error: unknown command'

if __name__ == '__main__':
    gobject.threads_init()
    dbus.glib.init_threads()
    
    usage = 'Usage: '+sys.argv[0]+' [options] remote_device [files]...'
    parser = OptionParser(usage)
    parser.add_option('-p', '--preferred', dest='preferred',
                      action='store_true', default=False,
                      help='Send images in size preferred by remote device')
    parser.add_option('-s', '--size', dest='size',
                      help='Use size of WIDTH*HEIGHT for resizing images '\
                      '(different resizing rules apply for specific transformation). '\
                      'Transformation might be selected either by -t option or '\
                      'by remote device capabilities.',
                      metavar='WIDTH*HEIGHT')
    parser.add_option('-t', '--transformation', dest='transformation',
                      help='Transformation used for resizing images. Default is '\
                      'stretch. stretch stretches images to size smaller than '\
                      'specified size (either by -s option or by remote device '\
                      'capabilities) preserving original size ratio, '\
                      'fill puts original image in a larger one with '\
                      'prefilled color, crop crops part of original image',
                      metavar='stretch|crop|fill')
    parser.add_option('-c', '--capabilities', dest='capabilities',
                      action='store_true', default=False,
                      help='Print out imaging capabilities of remote device and exit')
    parser.add_option('-l', '--local', dest='local_device',
                      default='00:00:00:00:00:00',
                      help='ADDRESS of Bluetooth adapter to connect from. Default is 00:00:00:00:00:00',
                      metavar='ADDRESS')
    parser.add_option('-r', '--remote-display', dest='remote_display',
                      action='store_true', default=False,
                      help='Start RemoteDisplay interactive shell after uploading all images')
    options, args = parser.parse_args()
    
    err1 = ''
    err2 = ''
    if len(args) < 1:
        err1 = 'error: Remote device address not specified'
    if (not options.capabilities) and len(args) < 2:
        err2 = 'error: No files to send'
    if err1 or err2:
        print usage
        print
        if err1: print err1
        if err2: print err2
        exit()
    
    tester = Tester(options, args)
