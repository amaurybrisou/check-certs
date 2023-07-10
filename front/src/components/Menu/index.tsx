import { Route, Routes } from 'react-router-dom'

const MenuItem = ({ name }: { name: string }) => {
  return <span>{name}</span>
}

export type MenuProp = {
  name: string
  path: string
}

export type MenuPropList = MenuProp[]

export default function Menu({ routes }: { routes: MenuPropList }) {
  return (
    <div>
      <Routes>
        {routes?.map((r: MenuProp) => {
          return (
            <Route
              key={r?.name}
              path={r?.path}
              element={<MenuItem name={r.name as string} />}
            >
              r.name
            </Route>
          )
        })}
      </Routes>
    </div>
  )
}
