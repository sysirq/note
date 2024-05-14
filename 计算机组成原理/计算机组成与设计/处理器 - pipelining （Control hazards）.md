![image](images/E54C01A1ABAB43549719415BDDE73FAF1600596558(1).png)

# Assume Branch Not Taken

One improvement over branch stalling is to predict that the conditional branch will not be taken and thus continue execution down the sequential instruction stream.

To discard instructions,we merely change the original control values to 0s,much as we did to stall for a load-use data hazard.The difference is that we must also change the three instructions in the IF,ID,and EX stages when the branch reaches the MEM stage;Discarding instructions,then,means we must be able to flush instructions in the IF,ID and EX stages of the pipeline.


# Reducing the Delay of Branches

One way to improve conditional branch performance is to reduce the cost of the taken branch.Thus far,we have assumed the next PC for branch is selected in the MEM stage,buf if we move the conditional branch execution earlier in the pipeling,then fewer instructions need be flushed.

![image](images/FCADE21C901E4875AF9B4349461323E31600598876(1).png)


# Dynamic Branch Prediction

Ideally,the accuracy(精准) of the predictor would match the taken branch frequency for these highly regular branches.

![image](images/27F3379E88414D1685993648477017291600600694(1).png)