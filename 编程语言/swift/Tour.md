# 变量

实用let定义常量，var定义变量

```swift
var a = 123
let b = 456
```

通常变量类型可以通过初始化时赋值的值，自动的推倒出来，但是有些情况需要我们指定变量类型(将类型写在变量后面，用冒号分)：

```swift
var a:Int = 123
```

值永远不会隐式转换为另一种类型。如果需要将值转换为不同的类型，请显式地创建所需类型的实例。

```swift
let label = "The width is "
let width = 94

let widthLabel = label + String(94)

print(widthLabel)
```

在字符串中包含值还有一种更简单的方法:将值写在括号中，并在括号前写一个反斜杠(\\)

```swift
let apples = 3
let appleSummary = "I have \(apples) apples"
print(appleSummary)
```

使用括号(\[])创建数组和字典，并通过在括号中写入索引或键来访问它们的元素。数组会随着添加元素而自动增长。

    var fruits = ["strawberries", "limes", "tangerines"]
    fruits[1] = "grapes"
    fruits.append("blueberries")
    print(fruits)

    var occupations = [
        "Malcolm": "Captain",
        "Kaylee": "Mechanic",
     ]
    occupations["Jayne"] = "Public Relations"

还可以使用括号创建空数组或字典。

```swift
let emptyArray: [String] = []
let emptyDictionary: [String: Float] = [:]
```

# 控制流

使用if和switch来创建条件，使用for-in、while和repeat-while来创建循环。条件或循环变量周围的括号是可选的。身体周围需要{}包裹

```swift
let individualScores = [75,43,103,87,12]
var teamScore = 0

for score in individualScores {
    if score > 50 {
        teamScore += 3
    } else {
        teamScore += 1  
    }
}
print(teamScore)
```

在if语句中，条件必须是布尔表达式——这意味着诸如if score{…}是一个错误，而不是与零的隐式比较

您可以在赋值(=)之后或在return之后写入if或switch，以根据条件选择一个值

```swift
let scoreDecoration = if teamScore > 10 {
    "🎉"
} else {
    ""
}
print("Score:", teamScore, scoreDecoration)
// Prints "Score: 11 🎉"
```

您可以一起使用if和let来处理可能丢失的值。这些值表示为可选值。可选值要么包含一个值，要么包含nil，以指示缺少一个值。在值的类型后面写一个问号，表示该值是可选的。

```swift
var optionalString: String? = "Hello"
print(optionalString == nil)
// Prints "false"


var optionalName: String? = "John Appleseed"
var greeting = "Hello!"
if let name = optionalName {
    greeting = "Hello, \(name)"
}
```

处理可选值的另一种方法是使用??操作符。如果缺少可选值，则使用默认值。

```swift
let nickname: String? = nil
let fullName: String = "John Appleseed"
let informalGreeting = "Hi \(nickname ?? fullName)"
```

一个Optional值和非Optional值的区别就在于：Optional值未经初始化虽然为nil，但普通变量连nil都没有

swift支持任何类型的数据和各种比较操作——它们不仅限于整数和相等性测试。

```swift
let vegetable = "red pepper"
switch vegetable {
case "celery":
    print("Add some raisins and make ants on a log.")
case "cucumber", "watercress":
    print("That would make a good tea sandwich.")
case let x where x.hasSuffix("pepper"):
    print("Is it a spicy \(x)?")
default:
    print("Everything tastes good in soup.")
}
// Prints "Is it a spicy red pepper?"
```

在执行匹配的switch case中的代码后，程序退出switch语句。执行不会继续到下一个case，因此您不需要在每个case的代码末尾显式地中断切换。

通过为每个键-值对提供一对名称，使用for-in来迭代字典中的项。字典是一个无序集合，因此它们的键和值以任意顺序迭代。

```swift
let interestingNumbers = [
    "Prime": [2, 3, 5, 7, 11, 13],
    "Fibonacci": [1, 1, 2, 3, 5, 8],
    "Square": [1, 4, 9, 16, 25],
]
var largest = 0
for (_, numbers) in interestingNumbers {
    for number in numbers {
        if number > largest {
            largest = number
        }
    }
}
print(largest)
// Prints "25"
```

使用while来重复代码块，直到条件发生变化。循环的条件可以在末尾，以确保循环至少运行一次。

```swift
var n = 2
while n < 100 {
    n *= 2
}
print(n)
// Prints "128"


var m = 2
repeat {
    m *= 2
} while m < 100
print(m)
// Prints "128"
```

使用. .<表示省略其上限的范围，并使用…创建包含两个值的范围。

```swift
var total = 0
for i in 0..<4 {
    total += i
}
print(total)
// Prints "6"
```

# 函数和闭包

使用func声明一个函数。通过在函数名后面加上圆括号,在圆括号中包含参数来调用函数。使用->将参数名称和类型与函数的返回类型分开。

```swift
func greet(person: String, day: String) -> String {
    return "Hello \(person), today is \(day)."
}
greet(person: "Bob", day: "Tuesday")
```

使用元组生成复合值—例如，从函数返回多个值。元组的元素既可以通过名称引用，也可以通过编号引用

```swift
func calculateStatistics(scores: [Int]) -> (min: Int, max: Int, sum: Int) {
    var min = scores[0]
    var max = scores[0]
    var sum = 0


    for score in scores {
        if score > max {
            max = score
        } else if score < min {
            min = score
        }
        sum += score
    }


    return (min, max, sum)
}
let statistics = calculateStatistics(scores: [5, 3, 100, 3, 9])
print(statistics.sum)
// Prints "120"
print(statistics.2)
// Prints "120"
```
函数可以嵌套。嵌套函数可以访问在外部函数中声明的变量。您可以使用嵌套函数来组织长函数或复杂函数中的代码。

```swift
func returnFifteen() -> Int {
    var y = 10
    func add() {
        y += 5
    }
    add()
    return y
}
returnFifteen()
```

函数是一类类型。这意味着一个函数可以返回另一个函数作为它的值。

```swift
func makeIncrementer() -> ((Int) -> Int) {
    func addOne(number: Int) -> Int {
        return 1 + number
    }
    return addOne
}
var increment = makeIncrementer()
increment(7)
```

函数可以将另一个函数作为其参数之一。

```swift
func hasAnyMatches(list: [Int], condition: (Int) -> Bool) -> Bool {
    for item in list {
        if condition(item) {
            return true
        }
    }
    return false
}
func lessThanTen(number: Int) -> Bool {
    return number < 10
}
var numbers = [20, 19, 7, 12]
hasAnyMatches(list: numbers, condition: lessThanTen)
```

函数实际上是闭包的一种特殊情况:可以稍后调用的代码块。闭包中的代码可以访问在创建闭包的作用域中可用的变量和函数之类的东西，即使闭包在执行时处于不同的作用域中—您已经看到了嵌套函数的示例。你可以通过用大括号({})包围代码来编写一个没有名称的闭包。使用in将参数和返回类型与主体分开。

```swift
var numbers = [20,9,7,12]

print(numbers.map({
    (number:Int)->Int in
    let result = 3*number
    return result
}))

```

有几种方法可以更简洁地编写闭包。当闭包的类型已经已知时，例如委托的回调，您可以省略其参数的类型、返回类型或两者都省略。单语句闭包隐式返回其唯一语句的值

```swift
let numbers = [20,19,7,12]
let mappedNumbers = numbers.map({ number in 3 * number })
print(mappedNumbers)
// Prints "[60, 57, 21, 36]"

```

# 对象与类

使用class后跟类名来创建类。类中的属性声明与常量或变量声明的编写方式相同，除了它是在类的上下文中。同样，方法声明与函数声明一样也以相同的方式编写。

通过在类名后面加上括号来创建类的实例。使用点语法访问实例的属性和方法。

```swift
class Shape {
    var numberOfSides = 0
    func simpleDescription() -> String {
        return "A shape with \(numberOfSides) sides."
    }
}

var shape = Shape()
shape.numberOfSides = 7
var shapeDescription = shape.simpleDescription()
print(shapeDescription)

```

这个版本的Shape类缺少一些重要的东西:在创建实例时设置类的初始化器。使用init创建一个

```swift
class NamedShape {
    var numberOfSides: Int = 0
    var name: String


    init(name: String) {
       self.name = name
    }


    func simpleDescription() -> String {
       return "A shape with \(numberOfSides) sides."
    }
}
```

请注意如何使用self来区分name属性和初始化式的name参数。在创建类的实例时，像传递函数调用一样传递初始化式的参数.每个属性都需要赋值——要么在其声明中(如numberOfSides)，要么在初始化器中(init)(如name)。

如果需要在对象被释放之前执行一些清理，可以使用deinit来创建一个释放器。

子类在类名之后包含它们的超类名，用冒号分隔。不要求类继承任何标准根类，因此您可以根据需要包含或省略超类。

重写父类方法的子类上的方法被标记为override —— 意外重写方法而没有override，编译器会将其检测为错误。编译器还会检测具有重写的方法，这些方法实际上没有重写超类中的任何方法。

```swift
class Square:NamedShape{
    var sideLength:Double
    
    init(sideLength:Double,name:String){
        self.sideLength = sideLength
        super.init(name: name)
        numberOfSides = 4
    }
    
    func area()->Double{
        return sideLength * sideLength
    }
    
    override func simpleDescription() -> String {
        return "A square with sides of length \(sideLength)"
    }
}

let test = Square(sideLength: 5.2, name: "my test square")
print(test.area())
print(test.simpleDescription())
```

除了存储的简单属性外，属性还可以有getter和setter。

```swift
class EquilateralTriangle: NamedShape {
    var sideLength: Double = 0.0


    init(sideLength: Double, name: String) {
        self.sideLength = sideLength
        super.init(name: name)
        numberOfSides = 3
    }


    var perimeter: Double {
        get {
             return 3.0 * sideLength
        }
        set {
            sideLength = newValue / 3.0
        }
    }


    override func simpleDescription() -> String {
        return "An equilateral triangle with sides of length \(sideLength)."
    }
}
var triangle = EquilateralTriangle(sideLength: 3.1, name: "a triangle")
print(triangle.perimeter)
// Prints "9.3"
triangle.perimeter = 9.9
print(triangle.sideLength)
// Prints "3.3000000000000003"
```

在perimeter的setter中，新值具有隐式名称newValue。可以在set后面的括号中提供显式名称.

注意，EquilateralTriangle类的初始化有三个不同的步骤:

- 设置子类声明的属性值。
- 调用父类的初始化项。
- 修改父类定义的属性值。此时也可以完成任何使用方法、getter或setter的附加设置工作。

如果你不需要计算属性，但仍然需要提供在设置新值之前和之后运行的代码，使用willSet和didSet。您提供的代码将在值在初始化器之外更改时运行。例如，下面的类确保三角形的边长总是与其正方形的边长相同。

```swift
class TriangleAndSquare {
    var triangle: EquilateralTriangle {
        willSet {
            square.sideLength = newValue.sideLength
        }
    }
    var square: Square {
        willSet {
            triangle.sideLength = newValue.sideLength
        }
    }
    init(size: Double, name: String) {
        square = Square(sideLength: size, name: name)
        triangle = EquilateralTriangle(sideLength: size, name: name)
    }
}
var triangleAndSquare = TriangleAndSquare(size: 10, name: "another test shape")
print(triangleAndSquare.square.sideLength)
// Prints "10.0"
print(triangleAndSquare.triangle.sideLength)
// Prints "10.0"
triangleAndSquare.square = Square(sideLength: 50, name: "larger square")
print(triangleAndSquare.triangle.sideLength)
// Prints "50.0"
```

当使用可选值时，您可以编写?在方法、属性和下标等操作之前。如果?前面的值是nil，那么？后面都会被忽略，整个表达式的值为nil。否则，将对可选值展开包装，并且?作用于打开的值。在这两种情况下，整个表达式的值都是可选值（Otherwise, the optional value is unwrapped, and everything after the ? acts on the unwrapped value. In both cases, the value of the whole expression is an optional value.）。

# 枚举和结构体

使用enum创建枚举。与类和所有其他命名类型一样，枚举可以具有与之关联的方法。

```swift
enum Rank:Int{
    case ace = 1
    case two,three,four,five,six,seven,eight,nine,ten
    case jack,queen,king
    
    func simpleDescription()->String{
        switch self {
        case .ace:
            return "ace"
        case .jack:
            return "jack"
        case .queen:
            return "queen"
        case .king:
            return "king"
        default:
            return String(self.rawValue)
        }
    }
}

let ace = Rank.ace
let aceRawValue = ace.rawValue

print(ace)
print(aceRawValue)

```

默认情况下，Swift分配的原始值从0开始，每次递增1，但你可以通过显式指定值来改变这种行为。在上面的例子中，Ace被显式地赋值为1，其余的原始值按顺序赋值。还可以使用字符串或浮点数作为枚举的原始类型。使用rawValue属性访问枚举用例的原始值。

使用init?(rawValue:)初始化器从原始值创建枚举实例。它返回匹配原始值的枚举情况，如果没有匹配的Rank，则返回nil。

```swift
if let convertedRank = Rank(rawValue: 3) {
    let threeDescription = convertedRank.simpleDescription()
}
```

枚举的case值是实际值，而不仅仅是编写其原始值的另一种方式。事实上，在没有有意义的原始值的情况下，您不必提供一个。

```swift
enum Suit {
    case spades, hearts, diamonds, clubs


    func simpleDescription() -> String {
        switch self {
        case .spades:
            return "spades"
        case .hearts:
            return "hearts"
        case .diamonds:
            return "diamonds"
        case .clubs:
            return "clubs"
        }
    }
}
let hearts = Suit.hearts
let heartsDescription = hearts.simpleDescription()

```

注意上面引用枚举hearts情况的两种方式:当为hearts常量赋值时，使用Suit.hearts，因为常量没有指定显式类型。在switch中，枚举用.hearts的缩写形式指代，因为self的值已知是Suit。只要值的类型已知，就可以使用缩写形式。

如果枚举具有原始值，则这些值将作为声明的一部分确定，这意味着特定枚举的每个实例始终具有相同的原始值。枚举用例的另一种选择是让值与用例相关联，这些值是在创建实例时确定的，对于枚举用例的每个实例，它们可能是不同的。可以将关联值看作是枚举用例的存储属性。例如，考虑从服务器请求日出和日落时间的情况。服务器要么响应请求的信息，要么响应出错的描述。

使用struct创建结构体。结构体支持许多与类相同的行为，包括方法和初始化器。结构体和类之间最重要的区别之一是，结构体在代码中传递时总是被复制，而类是通过引用传递的

```swift
struct Card {
    var rank: Rank
    var suit: Suit
    func simpleDescription() -> String {
        return "The \(rank.simpleDescription()) of \(suit.simpleDescription())"
    }
}
let threeOfSpades = Card(rank: .three, suit: .spades)
let threeOfSpadesDescription = threeOfSpades.simpleDescription()
```

# 并发性

使用async标记异步运行的函数。

```swift
func fetchUserID(from server: String) async -> Int {
    if server == "primary" {
        return 97
    }
    return 501
}
```

通过在异步函数前面写await来标记对该函数的调用。

```swift
func fetchUsername(from server: String) async -> String {
    let userID = await fetchUserID(from: server)
    if userID == 501 {
        return "John Appleseed"
    }
    return "Guest"
}
```

使用async let调用异步函数，让它与其他异步代码并行运行。当您使用它返回的值时，使用await。

```swift
func connectUser(to server: String) async {
    async let userID = fetchUserID(from: server)
    async let username = fetchUsername(from: server)
    let greeting = await "Hello \(username), user ID \(userID)"
    print(greeting)
}
```

使用Task从同步代码调用异步函数，而无需等待它们返回。

```swift
Task {
    await connectUser(to: "primary")
}
// Prints "Hello Guest, user ID 97"
```

使用任务组构建并发代码。

```swift
let userIDs = await withTaskGroup(of: Int.self) { group in
    for server in ["primary", "secondary", "development"] {
        group.addTask {
            return await fetchUserID(from: server)
        }
    }


    var results: [Int] = []
    for await result in group {
        results.append(result)
    }
    return results
}
```

actor与类类似，只是它们确保不同的异步函数可以同时安全地与同一actor的实例进行交互。

```swift
actor ServerConnection {
    var server: String = "primary"
    private var activeUsers: [Int] = []
    func connect() async -> Int {
        let userID = await fetchUserID(from: server)
        // ... communicate with server ...
        activeUsers.append(userID)
        return userID
    }
}
```

当您在actor上调用一个方法或访问它的一个属性时，您可以用await标记该代码，以表明它可能必须等待已经在actor上运行的其他代码完成。

```swift
let server = ServerConnection()
let userID = await server.connect()
```

# 协议和扩展

使用protocol声明一个协议。

```swift
protocol ExampleProtocol {
     var simpleDescription: String { get }
     mutating func adjust()
}
```

类、枚举和结构都可以采用协议。

```swift
class SimpleClass: ExampleProtocol {
     var simpleDescription: String = "A very simple class."
     var anotherProperty: Int = 69105
     func adjust() {
          simpleDescription += "  Now 100% adjusted."
     }
}
var a = SimpleClass()
a.adjust()
let aDescription = a.simpleDescription


struct SimpleStructure: ExampleProtocol {
     var simpleDescription: String = "A simple structure"
     mutating func adjust() {
          simpleDescription += " (adjusted)"
     }
}
var b = SimpleStructure()
b.adjust()
let bDescription = b.simpleDescription
```

请注意，SimpleStructure声明中使用了mutating关键字来标记修改结构的方法。SimpleClass的声明不需要将其任何方法标记为mutating，因为类上的方法总是可以修改类。

使用扩展向现有类型添加功能，例如新方法和计算属性。您可以使用扩展将协议一致性添加到其他地方声明的类型，甚至添加到从库或框架导入的类型.

```swift
extension Int: ExampleProtocol {
    var simpleDescription: String {
        return "The number \(self)"
    }
    mutating func adjust() {
        self += 42
    }
 }
print(7.simpleDescription)
// Prints "The number 7"
```

您可以像使用任何其他命名类型一样使用协议名称—例如，创建具有不同类型但都符合单一协议的对象集合。当您使用类型为盒装协议类型的值时，协议定义之外的方法不可用。

```swift
let protocolValue: any ExampleProtocol = a
print(protocolValue.simpleDescription)
// Prints "A very simple class.  Now 100% adjusted."
// print(protocolValue.anotherProperty)  // Uncomment to see the error

```

即使变量protocolValue的运行时类型是SimpleClass，编译器也会将其视为ExampleProtocol的给定类型。这意味着除了协议一致性之外，您不会意外访问类实现的方法或属性。

# 错误处理

您可以使用采用Error协议的任何类型来表示错误。

```swift
enum PrintError:Error{
    case outOfPaper
    case noToner
    case onFire
}
```

使用throw抛出错误，使用throws标记可以抛出错误的函数。如果在函数中抛出错误，该函数将立即返回，调用该函数的代码将处理错误。

```swift
func send(job: Int, toPrinter printerName: String) throws -> String {
    if printerName == "Never Has Toner" {
        throw PrinterError.noToner
    }
    return "Job sent"
}
```

有几种方法可以处理错误。一种方法是使用do-catch。在do块中，通过在前面写try来标记可能抛出错误的代码。在catch块中，除非您给错误起了一个不同的名字，否则错误将自动被命名为error。

```swift
do {
    let printerResponse = try send(job:1040,toPrinter: "Never has Toner")
    print(printerResponse)
}catch{
    print(error)
}
```

您可以提供多个catch块来处理特定的错误。就像在switch之后编写case一样。

```swift
do {
    let printerResponse = try send(job: 1440, toPrinter: "Gutenberg")
    print(printerResponse)
} catch PrinterError.onFire {
    print("I'll just put this over here, with the rest of the fire.")
} catch let printerError as PrinterError {
    print("Printer error: \(printerError).")
} catch {
    print(error)
}
```

另一种处理错误的方法是使用try?将结果转换为可选的。如果函数抛出错误，则丢弃特定的错误，结果为nil。否则，结果是可选的，包含函数返回的值。

```swift
let printerSuccess = try? send(job: 1884, toPrinter: "Mergenthaler")
let printerFailure = try? send(job: 1885, toPrinter: "Never Has Toner")
```

使用defer编写一段代码，该代码在函数中所有其他代码之后执行，就在函数返回之前。无论函数是否抛出错误，代码都将执行。您可以使用defer来编写相邻的设置和清理代码，即使它们需要在不同的时间执行。


```swift
var fridgeIsOpen = false
let fridgeContent = ["milk", "eggs", "leftovers"]


func fridgeContains(_ food: String) -> Bool {
    fridgeIsOpen = true
    defer {
        fridgeIsOpen = false
    }


    let result = fridgeContent.contains(food)
    return result
}
if fridgeContains("banana") {
    print("Found a banana")
}
print(fridgeIsOpen)
```

# 范型

在尖括号内写一个名字来创建泛型函数或类型。

```swift
func makeArray<Item>(repeating item: Item, numberOfTimes: Int) -> [Item] {
    var result: [Item] = []
    for _ in 0..<numberOfTimes {
         result.append(item)
    }
    return result
}
makeArray(repeating: "knock", numberOfTimes: 4)
```

您可以创建泛型形式的函数和方法，以及类、枚举和结构。

```swift
// Reimplement the Swift standard library's optional type
enum OptionalValue<Wrapped> {
    case none
    case some(Wrapped)
}
var possibleInteger: OptionalValue<Int> = .none
possibleInteger = .some(100)
```

在函数主体前面使用where来指定需求列表—例如，要求类型实现协议，要求两个类型相同，或者要求类具有特定的超类。

```swift
func anyCommonElements<T: Sequence, U: Sequence>(_ lhs: T, _ rhs: U) -> Bool
    where T.Element: Equatable, T.Element == U.Element
{
    for lhsItem in lhs {
        for rhsItem in rhs {
            if lhsItem == rhsItem {
                return true
            }
        }
    }
   return false
}
anyCommonElements([1, 2, 3], [3])
```

# 资料

<https://www.swift.org/about/>

<https://docs.swift.org/swift-book/documentation/the-swift-programming-language/guidedtour/>
