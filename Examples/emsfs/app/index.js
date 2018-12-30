const
React = require('react'),
ReactDOM = require('react-dom'),
{ useSpring, animated } = require('react-spring');

function
calc (x, y)
{
    return [
        -(y - window.innerHeight / 2) / 20,
        (x - window.innerWidth / 2) / 20, 1.1
    ]
}
function
trans (x, y, s)
{
    return `perspective(600px) rotateX(${x}deg) rotateY(${y}deg) scale(${s})`
}
function
Card ()
{
    const
    [spring_props, spring_set] = useSpring({
        xys: [0, 0, 1],
        config: { mass: 5, tension: 350, friction: 40 }
    });
    return React.createElement(
        animated.div, {
            className: "card",
            style: {
                transform: spring_props.xys.interpolate(trans)
            },
            onMouseMove (e)
            {
                return spring_set({ xys: calc(e.clientX, e.clientY) })
            },
            onMouseLeave ()
            {
                return spring_set({ xys: [0, 0, 1] })
            },
        })
}

ReactDOM.render(
    React.createElement(Card),
    document.getElementById('mount'))