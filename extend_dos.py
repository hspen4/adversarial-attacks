from calc_initial_evasion import filter_malware
from secml_malware.attack.whitebox.c_extend_dos_evasion import CExtendDOSEvasion
from secml.array import CArray

X = []
Y = []
i = 20 # num iterations
conf = 0.5 # confidence threshold

unoptimizable = 0
total_iters = 0
immediate = 0
success = 0
count = 0

model = filter_malware(X,Y,False)
attack = CExtendDOSEvasion(model, iterations=i, threshold=conf, pe_header_extension=4, is_debug=False, penalty_regularizer=0, chunk_hyper_parameter=4)

for code, name in zip(X,Y):
    _,_,_,final = attack.run(CArray(code), CArray(name[1]))
    # print(attack.confidences_)
    # print(final)
    if (len(attack.confidences_) < (i - 1)):
        total_iters = total_iters + len(attack.confidences_) - 1
    print(str(len(attack.confidences_) - 1))
    if final >= (attack.confidences_[0] - 0.02):
        unoptimizable = unoptimizable + 1
    if len(attack.confidences_) == 2:
        immediate = immediate + 1
    if final < conf:
        success = success + 1
    count = count + 1

print("Not optimized: " + str(unoptimizable) + "/" + str(count))
print("Successful: " + str(success) + "/" + str(count))
print("Average iterations to evade: " + str(total_iters / count))
print("Immediate evasions: " + str(immediate) + "/" + str(count))
