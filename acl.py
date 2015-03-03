#!/usr/bin/env python3

"""
Library to implement access list functions
"""
ACLList = {}

def mask_list(ip):
    a = int(ip/8)
    list = []
    for x in range(0,a):
        list.append(8)
    if a is not 4:
        list.append(int(ip%8))
        for x in range(a+1,4):
            list.append(0)
    return list
def match_ip(address,subnet):
    if address[0] not in range(subnet[0][0],subnet[0][1]):
        return False
    elif address[1] not in range(subnet[1][0],subnet[1][1]):
        return False
    elif address[2] not in range(subnet[2][0],subnet[2][1]):
        return False
    elif address[3] not in range(subnet[3][0],subnet[3][1]):
        return False
    else:
        return True
class Rule:
    def __init__(self,src_ip_prefix, dst_ip_prefix, proto, src_port, dst_port, priority,action):
        self.srcip = src_ip_prefix
        self.dstip = dst_ip_prefix
        self.proto = proto
        self.srcport = src_port
        self.dstport = dst_port
        self.priority = priority
        self.action = action
        self.next = None
    def getPriority(self):
            return self.priority
    def getNext(self):
            return self.next
    def setNext(self,newnext):
            self.next = newnext
    def __repr__(self):
        temp = self
        return ('{"'+temp.srcip+','+temp.dstip+','+temp.proto+','+temp.srcport+','+temp.dstport+','+temp.priority+'":"'+temp.action+'"}\n')
    def match_packet(self,srcip, dstip, proto, srcport, dstport):
        """
        print (self.srcip)
        print (self.dstip)
        print (self.srcport)
        print (self.dstport)
        print (self.proto)
        """
        
        skipsrcip = 0
        skipdstip = 0
        skipsrcport = 0
        skipdstport = 0
        skipproto = 0

        if self.srcport is "*":
            skipsrcport = 1
        if self.dstport is "*":
            skipdstport = 1
        if self.proto is "*":
            skipproto = 1
        if self.srcip is "*":
            skipsrcip = 1
        else:
            src_mask_bits = int(self.srcip.split('/')[1])
            src_ip_pref = self.srcip.split('/')[0].split('.')
            src_mask_map = mask_list(src_mask_bits)
            src_ip_range = [[int(src_ip_pref[i]),int(src_ip_pref[i])+pow(2,8-int(src_mask_map[i]))] for i in range(0,4)]
            srcip_list = [int(x) for x in srcip.split('.') ]
        if self.dstip is "*":
            skipdstip = 1
        else:
            dst_mask_bits = int(self.dstip.split('/')[1])
            dst_ip_pref = self.dstip.split('/')[0].split('.')
            dst_mask_map = mask_list(dst_mask_bits)
            dst_ip_range = [[int(dst_ip_pref[i]),int(dst_ip_pref[i])+pow(2,8-int(dst_mask_map[i]))] for i in range(0,4)]
            dstip_list = [int(x) for x in dstip.split('.') ]
        
        if skipsrcip is not 1:
            if match_ip(srcip_list,src_ip_range) is False:
                return False
        elif skipdstip is not 1:
            if match_ip(dstip_list,dst_ip_range) is False:
                return False
        elif skipproto is not 1:
            if proto is not self.proto:
                return False
        elif skipsrcport is not 1:
            if srcport is not self.srcport:
                return False
        elif skipdstport is not 1:
            if dstport is not self.dstport:
                return False
        return True
class AccessList:
    def __init__(self,aclname,aclaction):
        self.name = aclname
        self.implicit = aclaction
        self.rule = None
    def addrule(self,src_ip_prefix, dst_ip_prefix, proto, src_port, dst_port, priority,action):
        newrule = Rule(src_ip_prefix, dst_ip_prefix, proto, src_port, dst_port, priority,action)
        if self.rule is None:
            self.rule = newrule
            return True
        if int(priority) < int(self.rule.priority):
            newrule.next = self.rule
            self.rule = newrule
            return True
        temp = self.rule
        temp1 = temp
        while (temp is not None) and (int(temp.getPriority()) < int(priority)):
            temp1 = temp    
            temp = temp.getNext()
        if temp is not None:
            if temp.getPriority() is priority:
                return False
        newrule.setNext(temp)
        temp1.setNext(newrule)
        return True
    def size(self):
        count = 0
        temp = self.rule
        while temp is not None:
                temp = temp.getNext()
                count = count + 1
        return count
    def search(self,item):
        temp = self.rule
        while (temp is not None) and (temp.getPriority() is not item):
                temp = temp.getNext()
        if temp is not None:
                return True
        return False
    def removerule(self,item):
        if self.rule is None:
            return False
        if int(self.rule.getPriority()) is item:
                self.rule = self.rule.getNext()
                return True
        temp = self.rule
        while ((temp.getNext() is not None) and (int(temp.getNext().getPriority()) is not item) ):
                temp = temp.getNext()
        if temp.getNext() is None:
            return False
        temp.setNext(temp.getNext().getNext())
        return True
def Acl_list_create(name, def_action):
    if name in ACLList:
        print ("List already exists")
        return False
    newacl = AccessList(name,def_action)
    ACLList[name] = newacl
    print ("List created")
    return True
def Acl_add_rule(aclname,src_ip_prefix, dst_ip_prefix, proto, src_port, dst_port, priority,action):
    if aclname not in ACLList:
        print ("ACL doesn't exist")
        return False
    thisacl = ACLList[aclname]
    if thisacl.addrule(src_ip_prefix, dst_ip_prefix, proto, src_port, dst_port, priority,action) is True:
        print ("Rule added")
        return True
    else:
        print("Priority overlaps")
        return False
def Acl_del_rule(aclname, prio):
    if aclname not in ACLList:
        print ("ACL doesn't exist")
        return False
    thisacl = ACLList[aclname]
    if thisacl.removerule(prio) is True:
        print ("Rule deleted")
        return True
    else:
        print ("Rule doesn't exist")
        return False
def Acl_list_delete(aclname):
    if aclname in ACLList:
        del ACLList[aclname]
        print ("ACL deleted")
        return True
    return False
def Acl_show_rules(aclname,filename):
    if aclname not in ACLList:
        print ("ACL doesn't exist")
        return False
    thisacl = ACLList[aclname]
    with open(filename,'w') as f:
        f.write('{"Default":"'+thisacl.implicit+'"}\n')
        temp = thisacl.rule
        while temp is not None:
            f.write('{"'+temp.srcip+','+temp.dstip+','+temp.proto+','+temp.srcport+','+temp.dstport+','+temp.priority+'":"'+temp.action+'"}\n')
            temp = temp.getNext()
def Acl_show_all (filename):
    if len(ACLList) is 0:
        print ("No ACL to show")
    with open(filename,'w') as f:
        for acl in ACLList:
            thisacl = ACLList[acl]
            f.write('{"'+acl+'","Default":"'+thisacl.implicit+'"')
            temp = thisacl.rule
            while (temp is not None):
                f.write(',"'+temp.srcip+','+temp.dstip+','+temp.proto+','+temp.srcport+','+temp.dstport+','+temp.priority+'":"'+temp.action+'"')
                temp = temp.getNext()
            f.write('}\n')
def Acl_check_packet(aclname, srcip, dstip, proto, srcport, dstport):
    acl = ACLList[aclname]
    current = acl.rule
    while current is not None:
        #print (current.priority,current.match_packet(srcip, dstip, proto, srcport, dstport))
        if current.match_packet(srcip, dstip, proto, srcport, dstport) is True:
            return (current.action,current.priority)
        current = current.getNext()
    return (acl.implicit,-1)