import binascii
#import ida_kernwin
#import ida_funcs
from idc import GetFunctionName,SegName
import idautils
from idaapi import get_func
import os
f = open("C:/Users/sgd/Desktop/ida/result.txt", 'w+')
idaapi.autoWait()
for func in idautils.Functions():
    func1=idaapi.get_func(func)    
    flags = idc.GetFunctionFlags(func)
    flag_ret="."#R
    flag_far="."#F
    flag_lib="."#L
    flag_static="."#S
    flag_frame="."#B
    flag_type="."#T
    flag_bottomp="."#=
    
    flag=""
    
    if not (flags & FUNC_NORET):#"FUNC_NORET"
       flag_ret="R"
    
    if flags & FUNC_FAR:#"FUNC_FAR"
       flag_far="F"
   
    if flags & FUNC_LIB:#"FUNC_LIB"
       flag_lib="L"       
    
    if flags & FUNC_STATIC:#"FUNC_STATIC"
       flag_static="S"       
    
    if flags & FUNC_FRAME:#"FUNC_FRAME"
       flag_frame="B" 
        
    current_tinfo_ = idc.GetTinfo(func)
    if current_tinfo_ is not None:#T
       flag_type="T"
    if flags & FUNC_BOTTOMBP:
       flag_bottomp="=" 
    
    flag=flag_ret+" "+flag_far+" "+flag_lib+" "+flag_static+" "+flag_frame+" "+flag_type+" "+flag_bottomp
    funname=idaapi.get_func_name(func)#name
    seg=SegName(func)#text
    length=(func1.endEA-func1.startEA)#length
    arguements=func1.argsize#arguements
    
    local=func1.frsize+func1.frregs
    
    print >> f,funname.ljust(103),seg,('%.8X'%func),"%.8X" % length,"%.8X" % local,"%.8X" % arguements,flag
    
    
    
    
    
 












 # if flags & FUNC_THUNK:
    #   print "T" #"FUNC_FRAME"  
    
      
    #GetFunctionAttr(func,FUNCATTR_FRSIZE)
    #
    #print hex(GetFunctionAttr(func,FUNCATTR_FLAGS))
        #print 	
    #print GetMemberOffset()  
    
    #if flags & FUNC_THUNK:
     #  print "T"                         #hex(func), "FUNC_THUNK"   
    #if flags & FUNC_USERFAR:
     #  print hex(func), "FUNC_USERFAR"
    #if flags & FUNC_HIDDEN:
     #  print hex(func), "FUNC_HIDDEN"
  
    #if flags & FUNC_LIB:
     #  print hex(func), "FUNC_BOTTOMBP"
    
 #   if func1.does_return():
 #       print("R")   
 #   if not func1.does_return():
 #       print(".")
 #   if func1.is_far():
 #       print("F")
 #   if not func1.is_far():
 #       print(".")
 #   flags = idc.GetFunctionFlags(func)
 #   if flags & FUNC_LIB:
 #   continue


#print "Start: 0x%x, End: 0x%x" % (func1.startEA,func1.endEA)
#print hex(GetFunctionFlags(func))
#print idc.GetFunctionAttr(func, FUNCATTR_START)