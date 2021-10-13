# Cert-RNN: Towards Certifying the Robustness of Recurrent Neural Networks

Authors: Tianyu Du (Zhejiang University); Shouling Ji (Zhejiang University); Lujia Shen (Zhejiang University); Yao Zhang (Zhejiang University); Jinfeng Li (Zhejiang University); Jie Shi (Huawei International, Singapore); Chengfang Fang (Huawei International, Singapore); Jianwei Yin (Zhejiang University); Raheem Beyah (Georgia Institute of Technology); Ting Wang (Pennsylvania State University)

Keywords: deep learning, recurrent neural networks, robustness certification, natural language processing

## Abstract

Certifiable robustness, the functionality of verifying whether the given region surrounding a data point admits any adversarial example, provides guaranteed security for neural networks deployed in adversarial environments. A plethora of work has been proposed to certify the robustness of feed-forward networks, e.g., FCNs and CNNs. Yet, most existing methods cannot be directly applied to recurrent neural networks (RNNs), due to their sequential inputs and unique operations. In this paper, we present Cert-RNN, a general framework for certifying the robustness of RNNs. Specifically, through detailed analysis for the intrinsic property of the unique function in different ranges, we exhaustively discuss different cases for the exact formula of bounding planes, based on which we design several precise and efficient abstract transformers for the unique calculations in RNNs. Cert-RNN significantly outperforms the state-of-the-art methods (e.g., POPQORN [25]) in terms of (i) effectiveness – it provides much tighter robustness bounds, and (ii) efficiency – it scales to much more complex models. Through extensive evaluation, we validate Cert-RNN’s superior performance across various network architectures (e.g., vanilla RNN and LSTM) and applications (e.g., image classification, sentiment analysis, toxic comment detection, and malicious URL detection). For instance, for the RNN-2-32 model on the MNIST sequence dataset, the robustness bound certified by Cert-RNN is on average 1.86 times larger than that by POPQORN. Besides certifying the robustness of given RNNs, Cert-RNN also enables a range of practical applications including evaluating the provable effectiveness for various defenses (i.e., the defense with a larger robustness region is considered to be more robust), improving the robustness of RNNs (i.e., incorporating Cert-RNN with verified robust training) and identifying sensitive words (i.e., the word with the smallest certified robustness bound is considered to be the most sensitive word in a sentence), which helps build more robust and interpretable deep learning systems. We will open-source CertRNN for facilitating the DNN security research.

## Related

Present PPT: [https://nesa.zju.edu.cn/download/ppt/dty_slides_Cert-RNN.pdf](https://nesa.zju.edu.cn/download/ppt/dty_slides_Cert-RNN.pdf)

## Download

PDF: [Cert-RNN Towards Certifying the Robustness of Recurrent.pdf](../file/Cert-RNN Towards Certifying the Robustness of Recurrent.pdf)