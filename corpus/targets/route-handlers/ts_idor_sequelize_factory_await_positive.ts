// observation: User input is used directly to query an object via Sequelize without validating ownership inside a factory closure.
import { Request, Response, NextFunction } from 'express';

export function quantityCheckBeforeBasketItemUpdate() {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } });
      if (item) {
        res.json(item);
      }
    } catch (error) {
      next(error);
    }
  }
}
