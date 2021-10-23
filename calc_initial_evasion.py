# code partially adapted from github.com/pralab/secml_malware

import os
import secml_malware
from secml.array import CArray
from secml_malware.models.malconv import MalConv
from secml_malware.models.c_classifier_end2end_malware import CClassifierEnd2EndMalware, End2EndModel

# start malconv

net = MalConv()
net = CClassifierEnd2EndMalware(net)
net.load_pretrained_model()


# gets the confidence levels of each input executable initially

path = "secml_malware/data/malware_samples"
for _,file in enumerate(os.listdir(path)):
    loc = os.path.join(path,file)
    with open(loc,"rb") as opened:
        contents = opened.read()
    obj = End2EndModel.bytes_to_numpy(contents,net.get_input_max_length(),256,False)
    _, conf = net.predict(CArray(obj), True)
    print(file + " has confidence " + str(conf[0,1].item()))
