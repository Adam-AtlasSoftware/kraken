// cpp_shapes: C++ classes, virtual methods, a template and std::string.
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

class Shape {
public:
    explicit Shape(std::string name) : name_(std::move(name)) {}
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual double perimeter() const = 0;
    virtual std::string describe() const
    {
        return name_ + " area=" + std::to_string(static_cast<int>(area()));
    }
    const std::string &name() const { return name_; }

protected:
    std::string name_;
};

class Rect : public Shape {
public:
    Rect(double w, double h) : Shape("rect"), w_(w), h_(h) {}
    double area() const override { return w_ * h_; }
    double perimeter() const override { return 2 * (w_ + h_); }

private:
    double w_, h_;
};

class Square : public Rect {
public:
    explicit Square(double s) : Rect(s, s) { name_ = "square"; }
    std::string describe() const override { return "SQUARE:" + Rect::describe(); }
};

class Circle : public Shape {
public:
    explicit Circle(double r) : Shape("circle"), r_(r) {}
    double area() const override { return 3.14159 * r_ * r_; }
    double perimeter() const override { return 2 * 3.14159 * r_; }

private:
    double r_;
};

template <typename T>
class Accumulator {
public:
    void add(const T &v) { items_.push_back(v); }
    T sum() const
    {
        T s{};
        for (const T &v : items_)
            s += v;
        return s;
    }
    size_t size() const { return items_.size(); }

private:
    std::vector<T> items_;
};

static std::string join(const std::vector<std::string> &parts, const std::string &sep)
{
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i)
            out += sep;
        out += parts[i];
    }
    return out;
}

int main()
{
    std::vector<std::unique_ptr<Shape>> shapes;
    shapes.push_back(std::make_unique<Rect>(3, 4));
    shapes.push_back(std::make_unique<Square>(5));
    shapes.push_back(std::make_unique<Circle>(2));

    Accumulator<double> areas;
    Accumulator<std::string> names;
    std::vector<std::string> lines;
    double perim = 0;
    for (const auto &s : shapes) {
        areas.add(s->area());
        names.add(s->name() + ";");
        lines.push_back(s->describe());
        perim += s->perimeter();
    }
    std::printf("%s\n", join(lines, " | ").c_str());
    std::printf("total area %.2f perimeter %.2f over %zu shapes\n", areas.sum(), perim, areas.size());
    std::printf("names %s\n", names.sum().c_str());
    return 0;
}
