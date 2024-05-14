基于HDL的电路设计是独立于实现技术的，因此他能获得实现技术的提升而提升

# 设计方法

### 设计规格(Design Specification)

最小的设计规格是提供电路要实现的功能

### 设计划分

自顶向下

### 设计输入

HDL编写

行为描述：让设计人员专注于功能实现，而不是关注在晶体管之间的链接

### 仿真和功能验证

- 编写测试计划
- Testbench开发
- 执行测试，并进行对比

### 设计整合和验证

将子模块整合为 Top level module

### 门级综合

This  step produces a netlist of standard cells or a database that will configure a target FPGA.

### 后综合设计验证

### 布局布线