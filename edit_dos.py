from calc_initial_evasion import filter_malware
from secml_malware.attack.whitebox.c_header_evasion import CHeaderEvasion
from secml.array import CArray

X = []
Y = []
i = 50 # num iterations
conf = 0.5 # confidence threshold

unoptimizable = 0
total_iters = 0
immediate = 0
success = 0
count = 0

model = filter_malware(X,Y,False)
attack = CHeaderEvasion(model, iterations=i, threshold=conf, optimize_all_dos=False)

for code, name in zip(X,Y):
    _,_,_,final = attack.run(CArray(code), CArray(name[1]))
    print(attack.confidences_)
    print(final)
    total_iters = total_iters + len(attack.confidences_)
    print(len(attack.confidences_))
    if final == attack.confidences_[0]:
        unoptimizable = unoptimizable + 1
    if len(attack.confidences_) == 2:
        immediate = immediate + 1
    if final < conf:
        success = success + 1
    count = count + 1

print("Not optimized: " + str(unoptimizable) + "/" + str(count))
print("Successful: " + str(success) + "/" + str(count))
print("Average iterations: " + str(total_iters / count))
print("Immediate passes: " + str(immediate) + "/" + str(count))
