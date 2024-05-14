# Processes

- A private virtual address space
- An executable program
- A list of open handles
- A security context
- A process ID
- At least one thread of execution

Each process also points to its parent or creator process.If the parent no longer exists,this information is not updated.Therefore,it is possible for a process to refer to a nonexistent parent.